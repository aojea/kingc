package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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

type ExternalAPIServerResult struct {
	Endpoint string
	CACert   []byte
	// Signing info for KCM (Node CA)
	SigningKey  []byte
	SigningCert []byte
	// Service Account Keys/Pub
	SAKey []byte
	SAPub []byte
	// Front Proxy CA
	FrontProxyCACert []byte
	// Kubeconfigs (generated during CA lifecycle)
	AdminKubeconfig             string
	SchedulerKubeconfig         string
	ControllerManagerKubeconfig string
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
	// Verify Compute Engine API (compute.googleapis.com) explicitly if VerifyComputeAPI didn't catch it,
	// checking against the service list is more robust for "enabled" status.
	// Also explicitly check for 'iam.googleapis.com' if we need it for service accounts,
	// 'cloudresourcemanager.googleapis.com' for project checks, and
	// 'certificatemanager.googleapis.com' for certificate management, and
	// 'privateca.googleapis.com' for private certificate authority.
	if err := m.gce.CheckServicesEnabled(ctx, []string{
		"compute.googleapis.com",
	}); err != nil {
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
	klog.Infof("🚀 Creating cluster '%s' (%s) in region %s...", cfg.Metadata.Name, cfg.Spec.Kubernetes.Version, cfg.Spec.Region)

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

	// Create a temporary directory for all intermediate files
	tmpDir, err := os.MkdirTemp("", "kingc-install-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	// Cleanup temp dir unless retained (useful for debugging generated scripts)
	defer func() {
		if !retain {
			_ = os.RemoveAll(tmpDir)
		} else {
			klog.Infof("⚠️  Retaining temporary files in %s", tmpDir)
		}
	}()

	if err = m.Preflight(ctx); err != nil {
		return err
	}

	// 1. Networking
	if err := func() error {
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
			}
			if err := m.gce.CreateFirewallRules(ctx, basename(cfg.Metadata.Name), netName); err != nil {
				return err
			}
		}
		return nil
	}(); err != nil {
		return err
	}

	// 1.5 Reserve Static IP for Control Plane VM
	var cpName, cpZone, cpNet, cpSub string
	var cpIP string
	var localKubeconfig string
	if len(cfg.Spec.Networks) == 0 {
		return fmt.Errorf("no networks defined in spec")
	}
	cpNet = cfg.Spec.Networks[0].Name
	cpSub, err = resolveSubnet(cfg.Spec.Networks, cpNet, "")
	if err != nil {
		return fmt.Errorf("resolving CP network: %v", err)
	}
	cpZone = cfg.Spec.ControlPlane.Zone
	if cpZone == "" {
		cpZone = m.gce.GetDefaultZone(ctx)
	}
	if cpZone == "" {
		cpZone = "us-central1-a"
	}
	cpName = fmt.Sprintf("%s-cp", cfg.Metadata.Name)

	klog.Infof("  > Reserving static IP for Control Plane VM...")
	cpIP, err = m.gce.EnsureStaticIP(ctx, cpName, cfg.Spec.Region)
	if err != nil {
		return fmt.Errorf("failed to ensure static IP for control plane: %v", err)
	}

	// Parse the control plane endpoint IP into a URL
	u, err := url.Parse(fmt.Sprintf("https://%s", net.JoinHostPort(cpIP, "6443")))
	if err != nil {
		return fmt.Errorf("failed to parse control plane url: %v", err)
	}
	cfg.Spec.ExternalAPIServer = u

	// 2. Generate Bootstrap Token
	tokenID := randString(6)
	tokenSecret := randString(16)
	bootstrapToken := fmt.Sprintf("%s.%s", tokenID, tokenSecret)

	// 3. Format RuntimeConfig
	var rcBuilder strings.Builder
	firstRC := true
	for k, v := range cfg.Spec.RuntimeConfig {
		if !firstRC {
			rcBuilder.WriteString(",")
		}
		rcBuilder.WriteString(fmt.Sprintf("%s=%s", k, v))
		firstRC = false
	}

	repoVer := cfg.Spec.Kubernetes.Version
	parts := strings.Split(repoVer, ".")
	if len(parts) >= 2 {
		repoVer = strings.Join(parts[:2], ".")
	}

	templateData := map[string]interface{}{
		"ClusterName":              cfg.Metadata.Name,
		"ControlPlaneEndpoint":     cfg.Spec.ExternalAPIServer.Host,
		"ControlPlaneIP":           cfg.Spec.ExternalAPIServer.Hostname(),
		"KubernetesVersion":        cfg.Spec.Kubernetes.Version,
		"KubernetesRepoVersion":    repoVer,
		"PodSubnet":                cfg.Spec.Kubernetes.Networking.PodCIDR,
		"ServiceSubnet":            cfg.Spec.Kubernetes.Networking.ServiceCIDR,
		"KindnetImage":             "registry.k8s.io/networking/kindnet:v1.0.0",
		"CCMImage":                 "registry.k8s.io/cloud-provider-gcp/cloud-controller-manager:v35.0.0",
		"FeatureGates":             cfg.Spec.FeatureGates,
		"RuntimeConfig":            rcBuilder.String(),
		"BootstrapToken":           bootstrapToken,
		"DiscoveryTokenCaCertHash": "sha256:0000000000000000000000000000000000000000000000000000000000000000", // dummy hash for CP VM init
	}

	// Render base install script (startup.sh)
	baseInstallScript, err := m.renderTemplate("templates/startup.sh", templateData)
	if err != nil {
		return err
	}

	// Render kubeadm config
	kubeadmConfigDummy, err := m.renderTemplate("templates/kubeadm-config.yaml", templateData)
	if err != nil {
		return err
	}
	if len(cfg.Spec.KubeadmConfigPatches) > 0 {
		for _, patch := range cfg.Spec.KubeadmConfigPatches {
			kubeadmConfigDummy = kubeadmConfigDummy + "\n---\n" + patch
		}
	}

	cpStartupScript := fmt.Sprintf(`%s

# ---------------------------------------------------------
# Control Plane Bootstrap
# ---------------------------------------------------------
echo "👑 kingc: Writing kubeadm config..."
mkdir -p /etc/kubernetes
cat <<EOF > /etc/kubernetes/kubeadm-config.yaml
%s
EOF

echo "👑 kingc: Running Kubeadm Init..."
kubeadm init --config /etc/kubernetes/kubeadm-config.yaml --ignore-preflight-errors=NumCPU

echo "👑 kingc: Control Plane Bootstrapped"
`, baseInstallScript, kubeadmConfigDummy)

	tmpCPStartup := filepath.Join(tmpDir, "cp-startup.sh")
	if err := os.WriteFile(tmpCPStartup, []byte(cpStartupScript), 0644); err != nil {
		return fmt.Errorf("failed to write startup script: %v", err)
	}

	// 4. Provision Control Plane
	{
		defer m.measure("Control Plane Provisioning")()
		klog.Infof("  > Provisioning Control Plane VM (%s) with IP %s...", cpZone, cpIP)
		err = m.gce.CreateInstance(
			ctx,
			cpName, cpZone, cfg.Spec.ControlPlane.MachineType,
			cpNet, cpSub,
			config.DefaultImageFamily, "", tmpCPStartup,
			cpIP, "",
			[]string{
				basename(cfg.Metadata.Name),
				"kingc-role-control-plane",
			},
		)
		if err != nil {
			klog.Warningf("    (Instance warning: %v)", err)
		}
	}

	// 5. Wait for API Server to be ready
	if err := func() error {
		defer m.measure("Wait for API Server")()
		klog.Infof("  > Waiting for Kubernetes API Server (%s) to be ready...", cfg.Spec.ExternalAPIServer.String())
		timeout := 5 * time.Minute
		if err := m.waitForAPIServer(ctx, cfg.Spec.ExternalAPIServer, timeout); err != nil {
			return fmt.Errorf("control plane failed to initialize after %v: %v", timeout, err)
		}
		return nil
	}(); err != nil {
		return err
	}

	// 6. Retrieve Kubeconfig and CA certificate from Control Plane VM
	var adminKubeconfig string
	var caCert []byte
	{
		klog.Infof("  > Retrieving admin kubeconfig and CA cert from Control Plane VM...")
		adminKubeconfig, err = m.gce.RunSSHOutput(ctx, cpName, cpZone, "sudo cat /etc/kubernetes/admin.conf")
		if err != nil {
			return fmt.Errorf("failed to retrieve admin kubeconfig: %v", err)
		}
		caCertStr, err := m.gce.RunSSHOutput(ctx, cpName, cpZone, "sudo cat /etc/kubernetes/pki/ca.crt")
		if err != nil {
			return fmt.Errorf("failed to retrieve CA certificate: %v", err)
		}
		caCert = []byte(caCertStr)

		localKubeconfig = filepath.Join(tmpDir, "admin.conf")
		if err := os.WriteFile(localKubeconfig, []byte(adminKubeconfig), 0600); err != nil {
			return fmt.Errorf("failed to write kubeconfig to %s: %v", localKubeconfig, err)
		}
		klog.Infof("    ✅ Admin Kubeconfig generated locally at %s", localKubeconfig)
	}

	// Install Cloud Controller Manager
	{
		defer m.measure("Install CCM")()
		klog.Infof("  > Installing CCM...")

		ccmManifest, err := m.renderTemplate("templates/ccm.yaml", templateData)
		if err != nil {
			return err
		}

		klog.Infof("    - Installing Cloud Provider GCP...")

		tmpCCM := filepath.Join(tmpDir, "ccm.yaml")
		if err := os.WriteFile(tmpCCM, []byte(ccmManifest), 0644); err != nil {
			return err
		}

		cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", localKubeconfig, "apply", "-f", tmpCCM)
		if out, err := cmd.CombinedOutput(); err != nil {
			klog.Warningf("    ⚠️  Failed to install CCM: %v\nOutput: %s", err, out)
		}
	}

	// 7. Calculate actual CA hash
	caHash, err := calculateCACertHash(caCert)
	if err != nil {
		return fmt.Errorf("failed to calculate CA cert hash: %v", err)
	}
	templateData["DiscoveryTokenCaCertHash"] = caHash

	// 8. Prepare worker startup configuration with correct CA hash
	kubeadmConfigReal, err := m.renderTemplate("templates/kubeadm-config.yaml", templateData)
	if err != nil {
		return err
	}
	if len(cfg.Spec.KubeadmConfigPatches) > 0 {
		for _, patch := range cfg.Spec.KubeadmConfigPatches {
			kubeadmConfigReal = kubeadmConfigReal + "\n---\n" + patch
		}
	}

	// 9. Worker Pools
	{
		defer m.measure("Worker Groups Provisioning")()
		klog.Infof("  > Provisioning Worker Groups...")

		workerStartup := fmt.Sprintf(`%s

# ---------------------------------------------------------
# Worker Bootstrap
# ---------------------------------------------------------
echo "👑 kingc: Writing kubeadm config..."
mkdir -p /etc/kubernetes
cat <<EOF > /etc/kubernetes/kubeadm-config.yaml
%s
EOF
echo "👑 kingc: Joining cluster..."
kubeadm join --config /etc/kubernetes/kubeadm-config.yaml --ignore-preflight-errors=NumCPU
`, baseInstallScript, kubeadmConfigReal)

		tmpWorkerStartup := filepath.Join(tmpDir, "worker-startup.sh")
		if err := os.WriteFile(tmpWorkerStartup, []byte(workerStartup), 0644); err != nil {
			return fmt.Errorf("failed to write worker startup script: %v", err)
		}

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
				config.DefaultImageFamily, tmpWorkerStartup,
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
	// CNI and other addons
	{
		defer m.measure("Install CNI")()
		klog.Infof("  > Installing CNI...")
		//  CNI (kindnet)
		if !cfg.Spec.Kubernetes.Networking.DisableDefaultCNI {
			kindnetManifest, err := m.renderTemplate("templates/kindnet.yaml", templateData)
			if err != nil {
				return err
			}

			klog.Infof("    - Installing kindnet (v%s)...", "1.0.0") // Hardcoded for now or use variable

			tmpKindnet := filepath.Join(tmpDir, "kindnet.yaml")
			err = os.WriteFile(tmpKindnet, []byte(kindnetManifest), 0644)
			if err != nil {
				return fmt.Errorf("failed to write kindnet manifest to %s: %v", tmpKindnet, err)
			}

			cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", localKubeconfig, "apply", "-f", tmpKindnet)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to apply kindnet manifest: %v, output: %s", err, out)
			}
		} else {
			klog.Infof("    - Skipping default CNI (disabled in config)")
		}
	}

	// Finalize (Merge Kubeconfig)
	kcBytes, err := os.ReadFile(localKubeconfig)
	if err == nil {
		if err := mergeKubeconfig(cfg.Metadata.Name, kcBytes); err != nil {
			klog.Warningf("⚠️  Failed to merge kubeconfig: %v", err)
			// Fallback: write local file if merge fails?
			// Or just let user rely on the one in temp dir if they used --retain?
			// The temp dir is deleted by default.
			// Let's at least try to save it locally as fallback.
			fallbackConfig := fmt.Sprintf("%s.conf", cfg.Metadata.Name)
			if wErr := os.WriteFile(fallbackConfig, kcBytes, 0600); wErr == nil {
				klog.Infof("    Saved config to ./%s", fallbackConfig)
			}
		}
	} else {
		klog.Warningf("⚠️  Could not read temporary kubeconfig for merging: %v", err)
	}

	return nil
}

func (m *Manager) Delete(ctx context.Context, name string) error {
	defer m.measure("Delete Cluster " + name)()
	klog.Infof("🗑️  Deleting cluster %s...\n", name)

	var errs []error

	// Delete Instance Groups
	if err := func() error {
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
		return nil
	}(); err != nil {
		// do not fail on delete
	}

	// Delete Instance Templates
	if err := func() error {
		defer m.measure("Instance Templates Cleanup")()
		klog.Infof("  > Cleaning up Instance Templates...")
		filter := fmt.Sprintf("name:%s*", name)

		out, err := m.gce.RunQuiet(ctx, "compute", "instance-templates", "list", "--filter", filter, "--format=value(name)", "--quiet")
		if err != nil {
			klog.Warningf("    ⚠️  Failed to list instance templates: %v", err)
		} else {
			tmpls := strings.Fields(out)
			for _, t := range tmpls {
				klog.Infof("  > Deleting Template %s...", t)
				if _, err := m.gce.Run(ctx, "compute", "instance-templates", "delete", t, "--quiet"); err != nil && !gce.IsNotFoundError(err) {
					klog.Warningf("    ⚠️  Failed: %v", err)
					errs = append(errs, fmt.Errorf("delete template %s: %w", t, err))
				} else {
					klog.Infof("    ✅ Done")
				}
			}
		}
		return nil
	}(); err != nil {
		// do not fail on delete
	}

	// Delete Remaining Instances
	if err := func() error {
		defer m.measure("Instances Cleanup")()
		// We also verify instances to find regions if address is missing
		tags := []string{basename(name)}
		instances, err := m.gce.ListInstances(ctx, tags)
		if err != nil {
			klog.Warningf("    ⚠️  Failed to list instances: %v", err)
		} else {
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
		return nil
	}(); err != nil {
		// do not fail on delete
	}

	// Delete Firewall Rules
	// Check if rules exist by trying to delete them and ignoring NotFound
	if err := func() error {
		defer m.measure("Firewall Rules Cleanup")()
		klog.Infof("  > Deleting Firewall Rules...")
		// Use basename for firewall rules as they are created with it
		baseName := basename(name)
		rules := []string{baseName + "-internal", baseName + "-external"}
		fwArgs := append([]string{"compute", "firewall-rules", "delete"}, rules...)
		fwArgs = append(fwArgs, "--quiet")
		if _, err := m.gce.Run(ctx, fwArgs...); err != nil && !gce.IsNotFoundError(err) {
			klog.Warningf("    ⚠️  Failed: %v", err)
			errs = append(errs, fmt.Errorf("delete firewall rules: %w", err))
		} else {
			klog.Infof("    ✅ Done")
		}
		return nil
	}(); err != nil {
	}

	// Delete IP Addresses
	if err := func() error {
		defer m.measure("IP Addresses Cleanup")()
		klog.Infof("  > Cleaning up IP Addresses...")
		filter := fmt.Sprintf("name:kingc-cluster-%s*", name)
		addrs, err := m.gce.ListAddresses(ctx, filter)
		if err != nil {
			klog.Warningf("    ⚠️  Failed to list addresses: %v", err)
		} else {
			for _, addr := range addrs {
				klog.Infof("  > Deleting IP Address %s in %s...", addr.Name, addr.Region)
				if err := m.gce.DeleteAddress(ctx, addr.Name, addr.Region); err != nil && !gce.IsNotFoundError(err) {
					klog.Warningf("    ⚠️  Failed: %v", err)
					errs = append(errs, fmt.Errorf("delete address %s: %w", addr.Name, err))
				} else {
					klog.Infof("    ✅ Done")
				}
			}
		}
		return nil
	}(); err != nil {
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

func (m *Manager) ListNodes(ctx context.Context, clusterName string) ([]gce.Instance, error) {
	return m.gce.ListInstances(ctx, []string{basename(clusterName)})
}

func (m *Manager) ExportLogs(ctx context.Context, clusterName, outDir string) error {
	nodes, err := m.gce.ListInstances(ctx, []string{basename(clusterName)})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	var errs []error
	for _, node := range nodes {
		klog.Infof("  Retrieving logs from %s...", node.Name)
		// Capture logs (services + pods)
		cmd := `sudo sh -c "mkdir -p /tmp/kingc-logs && ` +
			`journalctl -u kubeblock -u kubelet -u containerd -u google-startup-scripts --no-pager > /tmp/kingc-logs/extensions.log && ` +
			`cp /var/log/kubelet.log /tmp/kingc-logs/kubelet.log 2>/dev/null || true && ` +
			`tar czf - -C /tmp/kingc-logs . -C /var/log pods containers"`

		out, err := m.gce.RunSSHRaw(ctx, node.Name, node.Zone, []string{cmd})
		if err != nil {
			klog.Warningf("  ⚠️  Failed to get logs from %s: %v", node.Name, err)
			errs = append(errs, err)
			continue
		}

		// stream untar
		nodeDir := filepath.Join(outDir, node.Name)
		if err := os.MkdirAll(nodeDir, 0755); err != nil {
			errs = append(errs, err)
			continue
		}

		if err := untar(nodeDir, bytes.NewReader(out)); err != nil {
			klog.Warningf("  ⚠️  Failed to extract logs for %s: %v", node.Name, err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("encountered %d errors collecting logs", len(errs))
	}
	return nil
}

func (m *Manager) waitForAPIServer(ctx context.Context, uri *url.URL, timeout time.Duration) error {
	// uri already contains scheme (https), so just append path.
	// We handle the url package shadowing by using a different variable name.
	target := *uri
	target.Path = "/healthz"
	healthURL := target.String()

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
			return fmt.Errorf("timed out waiting for API server at %s", healthURL)
		}

		// Create request with context to respect cancellation during request
		req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
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
