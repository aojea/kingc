package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/aojea/kingc/pkg/config"
	"github.com/aojea/kingc/pkg/gce"
	"k8s.io/klog/v2"
)

//go:embed templates/*
var templatesFS embed.FS

type Manager struct {
	gce *gce.Client
}

func NewManager(client *gce.Client) *Manager {
	return &Manager{gce: client}
}

func (m *Manager) Preflight(ctx context.Context) error {
	if err := m.gce.CheckGcloud(); err != nil {
		return err
	}
	if _, err := m.gce.GetCurrentProject(ctx); err != nil {
		return err
	}
	if err := m.gce.VerifyComputeAPI(ctx); err != nil {
		return err
	}
	return nil
}

func (m *Manager) measure(step string) func() {
	start := time.Now()
	klog.V(2).Infof("⏱️  [Start] %s", step)
	return func() {
		klog.Infof("⏱️  [Timing] %s took %v", step, time.Since(start))
	}
}

func (m *Manager) Create(ctx context.Context, cfg *config.Cluster, retain bool) (err error) {
	defer m.measure("Create Cluster " + cfg.Metadata.Name)()
	klog.Infof("🚀 Creating cluster '%s' (v%s) in region %s...", cfg.Metadata.Name, cfg.Spec.Kubernetes.Version, cfg.Spec.Region)

	// Ensure cleanup on failure unless retained
	defer func() {
		if err != nil && !retain {
			klog.Errorf("❌ Cluster creation failed: %v", err)
			klog.Info("🧹 Cleaning up resources (pass --retain to disable)...")
			if cleanupErr := m.Delete(context.Background(), cfg.Metadata.Name); cleanupErr != nil {
				klog.Errorf("⚠️  Failed to cleanup resources: %v", cleanupErr)
			}
		}
	}()

	if err = m.Preflight(ctx); err != nil {
		return err
	}

	// 1. Networking
	{
		defer m.measure("Networking Setup")()
		for _, net := range cfg.Spec.Networks {
			netName := net.Name
			isAuto := len(net.Subnets) == 0

			klog.Infof("  > Ensuring Network: %s (Auto: %v, MTU: %d, Profile: %s)\n", netName, isAuto, net.MTU, net.Profile)

			if !m.gce.NetworkExists(ctx, netName) {
				if err := m.gce.CreateNetwork(ctx, netName, isAuto, net.MTU, net.Profile); err != nil {
					return err
				}
				for _, sub := range net.Subnets {
					if err := m.gce.CreateSubnet(ctx, sub.Name, netName, cfg.Spec.Region, sub.CIDR); err != nil {
						return err
					}
				}
				if err := m.gce.CreateFirewallRules(ctx, cfg.Metadata.Name, netName); err != nil {
					return err
				}
			}
		}
	}

	// 2. Load Balancer / Endpoint
	var lbIP string
	{
		defer m.measure("Load Balancer Reservation")()
		klog.Infof("  > Reserving Regional External Passthrough Load Balancer IP...")
		// Use Control Plane region
		lbIP, err = m.gce.EnsureStaticIP(ctx, fmt.Sprintf("%s-api", cfg.Metadata.Name), cfg.Spec.ControlPlane.Region)
		if err != nil {
			return err
		}
	}

	// 3. Prepare Base Scripts (Pass Version info)

	// Format RuntimeConfig map to string "key=value,key2=value2" for CLI flag
	var rcBuilder strings.Builder
	firstRC := true
	for k, v := range cfg.Spec.RuntimeConfig {
		if !firstRC {
			rcBuilder.WriteString(",")
		}
		rcBuilder.WriteString(fmt.Sprintf("%s=%s", k, v))
		firstRC = false
	}

	// Calculate Repo Version (Major.Minor) from KubernetesVersion (Major.Minor.Patch)
	// e.g. v1.30.0 -> v1.30
	repoVer := cfg.Spec.Kubernetes.Version
	parts := strings.Split(repoVer, ".")
	if len(parts) >= 2 {
		repoVer = strings.Join(parts[:2], ".")
	}

	templateData := map[string]interface{}{
		"ClusterName":           cfg.Metadata.Name,
		"ControlPlaneEndpoint":  lbIP,
		"KubernetesVersion":     cfg.Spec.Kubernetes.Version,
		"KubernetesRepoVersion": repoVer,
		"PodSubnet":             cfg.Spec.Kubernetes.Networking.PodCIDR,
		"ServiceSubnet":         cfg.Spec.Kubernetes.Networking.ServiceCIDR,
		"KindnetVersion":        "v1.0.0", // TODO: Make configurable if needed
		"FeatureGates":          cfg.Spec.FeatureGates,
		"RuntimeConfig":         rcBuilder.String(),
	}

	// Render the base installation script
	baseInstallScript, err := m.renderTemplate("templates/startup.sh", templateData)
	if err != nil {
		return err
	}

	// 4. Prepare Control Plane Config & Script
	klog.Infof("  > Generating Kubeadm config...")
	kubeadmConfig, err := m.renderTemplate("templates/kubeadm-config.yaml", templateData)
	if err != nil {
		return err
	}

	if len(cfg.Spec.KubeadmConfigPatches) > 0 {
		for _, patch := range cfg.Spec.KubeadmConfigPatches {
			kubeadmConfig = kubeadmConfig + "\n---\n" + patch
		}
	}

	// Construct the CP startup script
	cpStartupScript := fmt.Sprintf(`%s

# ---------------------------------------------------------
# Control Plane Bootstrap
# ---------------------------------------------------------
echo "👑 kingc: Writing kubeadm config..."
mkdir -p /etc/kubernetes
cat <<EOF > /etc/kubernetes/kubeadm-config.yaml
%s
EOF

echo "👑 kingc: Running kubeadm init..."
kubeadm init --config /etc/kubernetes/kubeadm-config.yaml --upload-certs --ignore-preflight-errors=NumCPU

echo "👑 kingc: Control Plane Initialized"
`, baseInstallScript, kubeadmConfig)

	tmpCPStartup, _ := os.CreateTemp("", "cp-startup-*.sh")
	if err := os.WriteFile(tmpCPStartup.Name(), []byte(cpStartupScript), 0644); err != nil {
		return fmt.Errorf("failed to write startup script: %v", err)
	}
	defer func() { _ = os.Remove(tmpCPStartup.Name()) }()

	// 5. Provision Control Plane
	var cpName, cpZone, cpNet, cpSub string
	{
		defer m.measure("Control Plane Provisioning")()
		if len(cfg.Spec.Networks) == 0 {
			return fmt.Errorf("no networks defined in spec")
		}

		cpNet = cfg.Spec.Networks[0].Name
		cpSub, err = resolveSubnet(cfg.Spec.Networks, cpNet, "")
		if err != nil {
			return fmt.Errorf("resolving CP network: %v", err)
		}

		cpZone = cfg.Spec.ControlPlane.Zone
		cpName = fmt.Sprintf("%s-cp", cfg.Metadata.Name)

		// GCP External Passthrough LB delivers packets to the VM.
		klog.Infof("  > Provisioning Control Plane VM (%s)...", cpZone)
		err = m.gce.CreateInstance(
			ctx,
			cpName, cpZone, cfg.Spec.ControlPlane.MachineType,
			cpNet, cpSub,
			config.DefaultImageFamily, "", tmpCPStartup.Name(),
			"",
			[]string{
				basename(cfg.Metadata.Name),
				"kingc-role-control-plane",
			},
		)
		if err != nil {
			klog.Warningf("    (Instance warning: %v)", err)
		}

		// 5b. Configure Regional Load Balancer Logic
		klog.Infof("  > Configuring Regional Load Balancer...")
		baseName := basename(cfg.Metadata.Name)
		region := cfg.Spec.ControlPlane.Region
		hcName := baseName + "-hc"
		bsName := baseName + "-bs"
		frName := baseName + "-fr"
		igName := baseName + "-cp-ig" // Unmanaged Instance Group for CP

		// Health Check
		if err := m.gce.CreateRegionHealthCheck(ctx, hcName, region); err != nil {
			klog.Warningf("    (HC warning: %v)", err)
		}

		// Instance Group (Unmanaged)
		if err := m.gce.CreateUnmanagedInstanceGroup(ctx, igName, cpZone); err != nil {
			klog.Warningf("    (IG warning: %v)", err)
		}
		// Add instance to IG
		if err := m.gce.AddInstancesToGroup(ctx, igName, cpZone, cpName); err != nil {
			klog.Warningf("    (AddInstance warning: %v)", err)
		}

		// Backend Service
		if err := m.gce.CreateRegionBackendService(ctx, bsName, region, hcName); err != nil {
			klog.Warningf("    (BS warning: %v)", err)
		}
		// Add Backend
		if err := m.gce.AddRegionBackend(ctx, bsName, region, igName, cpZone); err != nil {
			klog.Warningf("    (AddBackend warning: %v)", err)
		}

		// Forwarding Rule
		if err := m.gce.CreateRegionForwardingRule(ctx, frName, region, bsName, lbIP); err != nil {
			klog.Warningf("    (FR warning: %v)", err)
		}
	}

	// 6. Wait for Control Plane Ready
	{
		defer m.measure("Wait for API Server")()
		klog.Infof("  > Waiting for Kubernetes API Server (%s:6443) to be ready...", lbIP)
		timeout := 5 * time.Minute
		if err := m.waitForAPIServer(ctx, lbIP, timeout); err != nil {
			return fmt.Errorf("control plane failed to initialize after %v: %v", timeout, err)
		}
	}

	// 7. Fetch Kubeconfig
	var localKubeconfig string
	{
		defer m.measure("Fetch Kubeconfig")()
		klog.Infof("  > Fetching admin.conf...")

		kc, err := m.GetKubeconfig(ctx, cfg.Metadata.Name)
		if err != nil {
			return fmt.Errorf("failed to fetch kubeconfig: %v", err)
		}

		localKubeconfig = fmt.Sprintf("%s.conf", cfg.Metadata.Name)
		if err := os.WriteFile(localKubeconfig, []byte(kc), 0600); err != nil {
			return fmt.Errorf("failed to write kubeconfig to %s: %v", localKubeconfig, err)
		}

		klog.Infof("✅ Cluster ready! Kubeconfig at: ./%s", localKubeconfig)
	}

	// 8. Install Addons (CNI, CCM)
	{
		defer m.measure("Install Addons")()
		klog.Infof("  > Installing Addons...")

		// A. CNI (kindnet)
		if !cfg.Spec.Kubernetes.Networking.DisableDefaultCNI {
			kindnetManifest, err := m.renderTemplate("templates/kindnet.yaml", templateData)
			if err != nil {
				return err
			}

			klog.Infof("    - Installing kindnet (v%s)...", "1.0.0") // Hardcoded for now or use variable

			tmpKindnet, _ := os.CreateTemp("", "kindnet-*.yaml")
			err = os.WriteFile(tmpKindnet.Name(), []byte(kindnetManifest), 0644)
			if err != nil {
				return fmt.Errorf("failed to write kindnet manifest to %s: %v", tmpKindnet.Name(), err)
			}
			defer func() {
				_ = os.Remove(tmpKindnet.Name())
			}()

			cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", localKubeconfig, "apply", "-f", tmpKindnet.Name())
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to apply kindnet manifest: %v, output: %s", err, out)
			}
		} else {
			klog.Infof("    - Skipping default CNI (disabled in config)")
		}

		// B. Cloud Controller Manager (external)
		// https://github.com/kubernetes/cloud-provider-gcp/blob/master/deploy/packages/default/manifest.yaml
		// Raw: https://raw.githubusercontent.com/kubernetes/cloud-provider-gcp/master/deploy/packages/default/manifest.yaml
		ccmURI := "https://raw.githubusercontent.com/kubernetes/cloud-provider-gcp/master/deploy/packages/default/manifest.yaml"
		klog.Infof("    - Installing Cloud Provider GCP...")
		cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", localKubeconfig, "apply", "-f", ccmURI)
		if out, err := cmd.CombinedOutput(); err != nil {
			// This might fail if network is restricted or URL is wrong.
			klog.Warningf("    ⚠️  Failed to install CCM (might need manual install): %v\nOutput: %s", err, out)
		}
	}

	// 9. Worker Pools
	{
		defer m.measure("Worker Groups Provisioning")()
		klog.Infof("  > Provisioning Worker Groups...")
		tokenCmd := "sudo /usr/bin/kubeadm token create --print-join-command"
		joinCommand, err := m.gce.RunSSHOutput(ctx, cpName, cpZone, tokenCmd)
		if err != nil {
			return fmt.Errorf("failed to get join command: %v", err)
		}
		joinCommand = strings.TrimSpace(joinCommand)

		workerStartup := fmt.Sprintf(`%s

# ---------------------------------------------------------
# Worker Bootstrap
# ---------------------------------------------------------
echo "👑 kingc: Joining cluster..."
%s --ignore-preflight-errors=NumCPU
`, baseInstallScript, joinCommand)

		tmpWorkerStartup, err := os.CreateTemp("", "worker-startup-*.sh")
		if err != nil {
			return fmt.Errorf("failed to create worker startup script: %v", err)
		}
		if err := os.WriteFile(tmpWorkerStartup.Name(), []byte(workerStartup), 0644); err != nil {
			return fmt.Errorf("failed to write worker startup script: %v", err)
		}
		defer func() { _ = os.Remove(tmpWorkerStartup.Name()) }()

		for _, grp := range cfg.Spec.WorkerGroups {
			klog.Infof("    [%s] Creating Instance Template and MIG (%d replicas) in %s...", grp.Name, grp.Replicas, grp.Zone)

			var networks, subnets []string

			if len(grp.Interfaces) > 0 {
				for _, iface := range grp.Interfaces {
					netName := iface.Network
					subName, err := resolveSubnet(cfg.Spec.Networks, netName, iface.Subnet)
					if err != nil {
						return err
					}

					networks = append(networks, netName)
					subnets = append(subnets, subName)
				}
			} else {
				networks = []string{cpNet}
				subnets = []string{cpSub}
			}

			tmplName := fmt.Sprintf("%s-%s-tmpl", cfg.Metadata.Name, grp.Name)
			if err := m.gce.CreateInstanceTemplate(
				ctx,
				tmplName, grp.MachineType, networks, subnets,
				config.DefaultImageFamily, tmpWorkerStartup.Name(),
				[]string{
					basename(cfg.Metadata.Name),
					"kingc-role-worker",
					"kingc-group-" + grp.Name,
				},
			); err != nil {
				klog.Warningf("    (Template warning: %v)", err)
			}

			migName := fmt.Sprintf("%s-%s-mig", cfg.Metadata.Name, grp.Name)
			if err := m.gce.CreateMIG(ctx, migName, tmplName, grp.Zone, grp.Replicas); err != nil {
				return err
			}
		}
	}

	// 9. Workers are next (Wait for them to join?)
	// Actually we provision workers after addons? Or before?
	// Existing code had workers after addons in block 7, but fetching kubeconfig was block 8 (after workers).
	// We moved fetch to 7, addons to 8. So workers should be 9.
	// WAIT, original code:
	// 5. Provision CP
	// 6. Wait for API
	// 7. Addons
	// 7b (was 7 too in comments). Worker Pools.
	// 8. Fetch Kubeconfig.

	// We want: 5 -> 6 -> Fetch (was 8) -> Addons (New) -> Workers (was 7b).
	// So we just need to ensure Workers block is after our new Addons block.

	return nil
}

func (m *Manager) Delete(ctx context.Context, name string) error {
	defer m.measure("Delete Cluster " + name)()
	klog.Infof("🗑️  Deleting cluster %s...\n", name)

	var errs []error

	// 1. Delete Regional LB Resources (Dependencies for Instance Groups)
	var instances []gce.Instance
	var addresses []gce.Address
	{
		defer m.measure("LB Resources Cleanup")()
		baseName := basename(name)
		addressName := baseName + "-api"

		// Gather regions from all possible regional resources
		targetRegions := make(map[string]bool)

		// A. Check Addresses
		var err error
		addresses, err = m.gce.ListAddresses(ctx, "name="+addressName)
		if err != nil {
			klog.Warningf("    ⚠️  Failed to list addresses: %v", err)
		} else {
			for _, addr := range addresses {
				if addr.Region != "" {
					targetRegions[addr.Region] = true
				}
			}
		}

		// B. Check Forwarding Rules
		frs, err := m.gce.ListForwardingRules(ctx, "name:"+baseName+"*")
		if err != nil {
			klog.Warningf("    ⚠️  Failed to list forwarding rules: %v", err)
		} else {
			for _, fr := range frs {
				if fr.Region != "" {
					targetRegions[fr.Region] = true
				}
			}
		}

		// C. Check Backend Services
		bss, err := m.gce.ListBackendServices(ctx, "name:"+baseName+"*")
		if err != nil {
			klog.Warningf("    ⚠️  Failed to list backend services: %v", err)
		} else {
			for _, bs := range bss {
				if bs.Region != "" {
					targetRegions[bs.Region] = true
				}
			}
		}

		// We also verify instances to find regions if address is missing
		tags := []string{basename(name)}
		instances, err = m.gce.ListInstances(ctx, tags)
		if err != nil {
			klog.Warningf("    ⚠️  Failed to list instances: %v", err)
		} else {
			for _, inst := range instances {
				if len(inst.Zone) > 2 {
					reg := inst.Zone[:len(inst.Zone)-2]
					targetRegions[reg] = true
				}
			}
		}

		for region := range targetRegions {
			klog.Infof("  > Cleaning up LB Resources in %s...", region)
			// FR
			if err := m.gce.DeleteRegionForwardingRule(ctx, baseName+"-fr", region); err != nil && !gce.IsNotFoundError(err) {
				klog.V(4).Infof("Ignored error deleting forwarding rule: %v", err)
			}
			// BS
			if err := m.gce.DeleteRegionBackendService(ctx, baseName+"-bs", region); err != nil && !gce.IsNotFoundError(err) {
				klog.V(4).Infof("Ignored error deleting backend service: %v", err)
			}
			// HC
			if err := m.gce.DeleteRegionHealthCheck(ctx, baseName+"-hc", region); err != nil && !gce.IsNotFoundError(err) {
				klog.V(4).Infof("Ignored error deleting health check: %v", err)
			}
			klog.Infof("    ✅ Done (Best Effort)")
		}
	}

	// 2. Delete Instance Groups
	{
		defer m.measure("Instance Groups Cleanup")()
		klog.Infof("  > Cleaning up Instance Groups...")
		filter := fmt.Sprintf("name:%s*", name)
		groups, err := m.gce.ListInstanceGroups(ctx, filter)
		if err != nil {
			klog.Warningf("    ⚠️  Failed to list instance groups: %v", err)
			errs = append(errs, fmt.Errorf("list instance groups: %w", err))
		} else {
			for _, g := range groups {
				if strings.Contains(g.Name, "mig") {
					klog.Infof("  > Deleting MIG %s in %s...", g.Name, g.Zone)
					if err := m.gce.DeleteMIG(ctx, g.Name, g.Zone); err != nil && !gce.IsNotFoundError(err) {
						klog.Warningf("    ⚠️  Failed: %v", err)
						errs = append(errs, fmt.Errorf("delete MIG %s: %w", g.Name, err))
					} else {
						klog.Infof("    ✅ Done")
					}
				} else {
					klog.Infof("  > Deleting Unmanaged IG %s in %s...", g.Name, g.Zone)
					if err := m.gce.DeleteUnmanagedInstanceGroup(ctx, g.Name, g.Zone); err != nil && !gce.IsNotFoundError(err) {
						klog.Warningf("    ⚠️  Failed: %v", err)
						errs = append(errs, fmt.Errorf("delete IG %s: %w", g.Name, err))
					} else {
						klog.Infof("    ✅ Done")
					}
				}
			}
		}
	}

	// 3. Delete Remaining Instances
	{
		defer m.measure("Instances Cleanup")()
		if len(instances) > 0 {
			for _, inst := range instances {
				klog.Infof("  > Deleting Instance %s in %s...", inst.Name, inst.Zone)
				if _, err := m.gce.Run(ctx, "compute", "instances", "delete", inst.Name, "--zone", inst.Zone, "--quiet"); err != nil && !gce.IsNotFoundError(err) {
					klog.Warningf("    ⚠️  Failed: %v", err)
					errs = append(errs, fmt.Errorf("delete instance %s: %w", inst.Name, err))
				} else {
					klog.Infof("    ✅ Done")
				}
			}
		}
	}

	// 4. Delete Addresses
	{
		defer m.measure("Address Cleanup")()
		for _, addr := range addresses {
			klog.Infof("  > Deleting Address %s...", addr.Name)
			if err := m.gce.DeleteAddress(ctx, addr.Name, addr.Region); err != nil && !gce.IsNotFoundError(err) {
				klog.Warningf("    ⚠️  Failed: %v", err)
				errs = append(errs, fmt.Errorf("delete address %s: %w", addr.Name, err))
			} else {
				klog.Infof("    ✅ Done")
			}
		}
	}

	// 5. Delete Firewall Rules
	// Check if rules exist by trying to delete them and ignoring NotFound
	{
		defer m.measure("Firewall Rules Cleanup")()
		klog.Infof("  > Deleting Firewall Rules...")
		rules := []string{name + "-internal", name + "-external"}
		fwArgs := append([]string{"compute", "firewall-rules", "delete"}, rules...)
		fwArgs = append(fwArgs, "--quiet")
		if _, err := m.gce.Run(ctx, fwArgs...); err != nil && !gce.IsNotFoundError(err) {
			klog.Warningf("    ⚠️  Failed: %v", err)
			errs = append(errs, fmt.Errorf("delete firewall rules: %w", err))
		} else {
			klog.Infof("    ✅ Done")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup failed with %d errors: %v", len(errs), errs)
	}
	klog.Infof("✨ Cluster %s deleted successfully", name)
	return nil
}

func (m *Manager) renderTemplate(path string, data interface{}) (string, error) {
	t, err := template.ParseFS(templatesFS, path)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (m *Manager) waitForAPIServer(ctx context.Context, ip string, timeout time.Duration) error {
	url := fmt.Sprintf("https://%s/healthz", net.JoinHostPort(ip, "6443"))
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Since(start) > timeout {
			return fmt.Errorf("timed out waiting for API server at %s", url)
		}

		// Create request with context to respect cancellation during request
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		fmt.Print(".")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func resolveSubnet(networks []config.NetworkSpec, netName, explicitSubnet string) (string, error) {
	if explicitSubnet != "" {
		return explicitSubnet, nil
	}
	for _, n := range networks {
		if n.Name == netName {
			if len(n.Subnets) == 0 {
				if netName == "default" {
					return "default", nil
				}
				return netName, nil
			}
			if len(n.Subnets) == 1 {
				return n.Subnets[0].Name, nil
			}
			return "", fmt.Errorf("network '%s' has multiple subnets; explicit subnet required", netName)
		}
	}
	return "", fmt.Errorf("network '%s' not found in config", netName)
}

func basename(name string) string {
	return "kingc-cluster-" + name
}

func (m *Manager) ListClusters(ctx context.Context) ([]string, error) {
	// Find all control planes
	instances, err := m.gce.ListInstances(ctx, []string{"kingc-role-control-plane"})
	if err != nil {
		return nil, err
	}
	clusters := make(map[string]bool)
	for _, inst := range instances {
		for _, tag := range inst.Tags.Items {
			if strings.HasPrefix(tag, "kingc-cluster-") {
				name := strings.TrimPrefix(tag, "kingc-cluster-")
				clusters[name] = true
			}
		}
	}
	var result []string
	for c := range clusters {
		result = append(result, c)
	}
	return result, nil
}

func (m *Manager) ListNodes(ctx context.Context, clusterName string) ([]gce.Instance, error) {
	return m.gce.ListInstances(ctx, []string{basename(clusterName)})
}

func (m *Manager) GetKubeconfig(ctx context.Context, clusterName string) (string, error) {
	// Find a control plane node
	instances, err := m.gce.ListInstances(ctx, []string{basename(clusterName), "kingc-role-control-plane"})
	if err != nil {
		return "", err
	}
	if len(instances) == 0 {
		return "", fmt.Errorf("no control plane found for cluster %s", clusterName)
	}
	cp := instances[0]
	// Cat the kubeconfig
	out, err := m.gce.RunSSHOutput(ctx, cp.Name, cp.Zone, "sudo cat /etc/kubernetes/admin.conf")
	if err != nil {
		return "", fmt.Errorf("failed to retrieve kubeconfig: %v", err)
	}
	return strings.TrimSpace(out), nil
}

func (m *Manager) ExportLogs(ctx context.Context, clusterName, outDir string) error {
	nodes, err := m.ListNodes(ctx, clusterName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	var errs []error
	for _, node := range nodes {
		// Capture startup script logs
		klog.Infof("  Retrieving logs from %s...", node.Name)
		out, err := m.gce.RunSSHOutput(ctx, node.Name, node.Zone, "sudo journalctl -u google-startup-scripts --no-pager && sudo journalctl -u kubelet --no-pager -n 100")
		if err != nil {
			klog.Warningf("  ⚠️ Failed to get logs from %s: %v", node.Name, err)
			errs = append(errs, err)
			continue
		}
		fName := fmt.Sprintf("%s/%s.log", outDir, node.Name)
		if err := os.WriteFile(fName, []byte(out), 0644); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("encountered %d errors collecting logs", len(errs))
	}
	return nil
}
