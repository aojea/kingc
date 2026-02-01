package cluster

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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
		"certificatemanager.googleapis.com",
		"privateca.googleapis.com",
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
			}
			if err := m.gce.CreateFirewallRules(ctx, basename(cfg.Metadata.Name), netName); err != nil {
				return err
			}
		}
	}

	// 1.5 Ensure External APIServer (New Architecture)
	{
		defer m.measure("Ensure External APIServer")()

		if len(cfg.Spec.Networks) == 0 {
			return fmt.Errorf("no networks defined in spec")
		}

		netName := cfg.Spec.Networks[0].Name
		subName := ""
		if len(cfg.Spec.Networks[0].Subnets) > 0 {
			subName = cfg.Spec.Networks[0].Subnets[0].Name
		} else {
			subName = netName // Auto mode?
		}

		// We need a Zone.
		zone := cfg.Spec.ControlPlane.Zone
		if zone == "" {
			zone = m.gce.GetDefaultZone(ctx)
		}
		if zone == "" {
			// Fallback or error?
			klog.Warning("No zone specified for External APIServer, guessing us-central1-a")
			zone = "us-central1-a"
		}

		ep, err := m.EnsureExternalAPIServer(ctx, cfg, zone, netName, subName)
		if err != nil {
			return fmt.Errorf("failed to ensure external apiserver: %v", err)
		}
		// Parse the endpoint IP into a URL
		u, err := url.Parse(fmt.Sprintf("https://%s:6443", ep))
		if err != nil {
			return fmt.Errorf("failed to parse external apiserver url: %v", err)
		}
		cfg.Spec.ExternalAPIServer = u
	}

	// 2. Load Balancer / Endpoint
	klog.Infof("  > Using External APIServer at %s", cfg.Spec.ExternalAPIServer.String())
	// 6. Wait for Control Plane Ready
	{
		defer m.measure("Wait for API Server")()
		klog.Infof("  > Waiting for Kubernetes API Server (%s) to be ready...", cfg.Spec.ExternalAPIServer.String())
		timeout := 5 * time.Minute
		if err := m.waitForAPIServer(ctx, cfg.Spec.ExternalAPIServer, timeout); err != nil {
			return fmt.Errorf("control plane failed to initialize after %v: %v", timeout, err)
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
		"ControlPlaneEndpoint":  cfg.Spec.ExternalAPIServer,
		"KubernetesVersion":     cfg.Spec.Kubernetes.Version,
		"KubernetesRepoVersion": repoVer,
		"PodSubnet":             cfg.Spec.Kubernetes.Networking.PodCIDR,
		"ServiceSubnet":         cfg.Spec.Kubernetes.Networking.ServiceCIDR,
		"KindnetImage":          "registry.k8s.io/networking/kindnet:v1.0.0",
		"CCMImage":              "registry.k8s.io/cloud-provider-gcp/cloud-controller-manager:v35.0.0",
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
	// apiserver and etcd are already running in the external apiserver
	kubeadmArgs := "--upload-certs --ignore-preflight-errors=NumCPU --skip-phases=etcd,control-plane/apiserver"

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
kubeadm init --config /etc/kubernetes/kubeadm-config.yaml %s

echo "👑 kingc: Control Plane Initialized"
`, baseInstallScript, kubeadmConfig, kubeadmArgs)

	tmpCPStartup := filepath.Join(tmpDir, "cp-startup.sh")
	if err := os.WriteFile(tmpCPStartup, []byte(cpStartupScript), 0644); err != nil {
		return fmt.Errorf("failed to write startup script: %v", err)
	}

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
			config.DefaultImageFamily, "", tmpCPStartup,
			"",
			[]string{
				basename(cfg.Metadata.Name),
				"kingc-role-control-plane",
			},
		)
		if err != nil {
			klog.Warningf("    (Instance warning: %v)", err)
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

		localKubeconfig = filepath.Join(tmpDir, "admin.conf")
		if err := os.WriteFile(localKubeconfig, []byte(kc), 0600); err != nil {
			return fmt.Errorf("failed to write kubeconfig to %s: %v", localKubeconfig, err)
		}

		klog.Infof("    ✅ Kubeconfig fetched (internal)")
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

		// B. Cloud Controller Manager (external)
		{
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

	// 10. Finalize (Merge Kubeconfig)
	// Read from temp and merge into KUBECONFIG
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

	// Delete Remaining Instances
	{
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
	}

	// Delete Firewall Rules
	// Check if rules exist by trying to delete them and ignoring NotFound
	{
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

func untar(dst string, r io.Reader) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer func() {
		_ = gzr.Close()
	}()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case header == nil:
			continue
		}
		target := filepath.Join(dst, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			_ = f.Close()
		}
	}
}

func (m *Manager) EnsureExternalAPIServer(ctx context.Context, cfg *config.Cluster, zone, network, subnet string) (string, error) {
	name := fmt.Sprintf("%s-apiserver", basename(cfg.Metadata.Name))

	// Assume image is in the current project's GCR
	image := config.DefaultAPIServerImage

	klog.Infof("  > Ensuring External APIServer instance %s (Image: %s)...", name, image)

	// Check if already exists
	ip, err := m.gce.EnsureStaticIP(ctx, name, cfg.Spec.Region)
	if err != nil {
		return "", err
	}

	// --- PKI Setup with Google CAS ---
	klog.Infof("  > Configuring Public Key Infrastructure (Google CAS)...")
	casRegion := cfg.Spec.Region // Use same region for CAS
	poolID := fmt.Sprintf("kingc-pool-%s", cfg.Metadata.Name)
	caID := fmt.Sprintf("kingc-ca-%s", cfg.Metadata.Name)

	// 1. Ensure Pool
	if err := m.gce.CreateCASPool(ctx, poolID, casRegion); err != nil {
		return "", fmt.Errorf("failed to create CAS pool: %v", err)
	}
	// 2. Ensure Root CA
	if err := m.gce.CreateCASRootCA(ctx, poolID, casRegion, caID, "kingc-ca"); err != nil {
		return "", fmt.Errorf("failed to create CAS Root CA: %v", err)
	}

	// 3. Generate CSR for API Server
	// Generate local key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate rsa key: %v", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	// CSR
	subj := pkix.Name{
		CommonName:   "kube-apiserver",
		Organization: []string{"kingc"},
	}
	// Add SANs: Localhhost, IP, kubernetes service IP
	dnsNames := []string{
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local",
		"localhost",
		name,
	}
	// Calculate the first IP of the Service CIDR (e.g. 10.96.0.1 for 10.96.0.0/12)
	svcPrefix, err := netip.ParsePrefix(cfg.Spec.Kubernetes.Networking.ServiceCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse service cidr: %v", err)
	}
	svcIP := svcPrefix.Addr().Next() // First IP is usually gateway/apiserver

	ips := []net.IP{
		net.ParseIP(ip),
		net.ParseIP("127.0.0.1"),
		net.ParseIP(svcIP.String()),
	}

	template := x509.CertificateRequest{
		Subject:     subj,
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// 4. Sign CSR
	certPEM, err := m.gce.SignCASCertificate(ctx, csrPEM, poolID, casRegion, caID)
	if err != nil {
		return "", fmt.Errorf("failed to sign certificate: %v", err)
	}

	// 4.5 Get Root CA
	caPEM, err := m.gce.GetCASRootCertificate(ctx, poolID, casRegion, caID)
	if err != nil {
		return "", fmt.Errorf("failed to get root CA: %v", err)
	}

	// 5. Setup Service Account Keys
	// CAS is not used for SA keys (JWT signing), so we generate them locally.
	// We generate them here ensuring the Manager is the source of truth.
	saPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate sa key: %v", err)
	}
	saKeyBytes := x509.MarshalPKCS1PrivateKey(saPrivKey)
	saKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: saKeyBytes})

	saPubKeyBytes, err := x509.MarshalPKIXPublicKey(&saPrivKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal sa public key: %v", err)
	}
	saPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: saPubKeyBytes})

	// 6. Embed generic startup script
	startupScript := `#! /bin/bash
mkdir -p /var/lib/kingc/pki
cd /var/lib/kingc/pki
# Generate Tokens
if [ ! -f tokens.csv ]; then
    echo "admin-token,admin,uid,system:masters" > tokens.csv
fi
chmod 600 *
`
	mounts := []string{
		"host-path=/var/lib/kingc/pki,mount-path=/var/run/kubernetes,mode=rw",
	}

	// Append to startup script to write certs and keys
	startupScript += fmt.Sprintf(`
echo "%s" > /var/lib/kingc/pki/apiserver.key
echo "%s" > /var/lib/kingc/pki/apiserver.crt
echo "%s" > /var/lib/kingc/pki/ca.crt
echo "%s" > /var/lib/kingc/pki/sa.key
echo "%s" > /var/lib/kingc/pki/sa.pub
`, string(keyPEM), string(certPEM), string(caPEM), string(saKeyPEM), string(saPubPEM))

	args := []string{
		"--secure-port=6443",
		"--service-cluster-ip-range=" + cfg.Spec.Kubernetes.Networking.ServiceCIDR,
		"--service-account-key-file=/var/run/kubernetes/sa.pub",
		"--service-account-signing-key-file=/var/run/kubernetes/sa.key",
		"--service-account-issuer=https://kubernetes.default.svc.cluster.local",
		"--token-auth-file=/var/run/kubernetes/tokens.csv",
		"--authorization-mode=Node,RBAC",
		"--advertise-address=" + ip,
		"--tls-cert-file=/var/run/kubernetes/apiserver.crt",
		"--tls-private-key-file=/var/run/kubernetes/apiserver.key",
		"--client-ca-file=/var/run/kubernetes/ca.crt",
	}

	meta := map[string]string{
		"startup-script": startupScript,
	}

	tags := []string{basename(cfg.Metadata.Name), "kingc-role-apiserver"}

	// Create Instance
	err = m.gce.CreateContainerInstance(
		ctx,
		name, zone, cfg.Spec.ControlPlane.MachineType,
		network, subnet,
		image,
		mounts,
		nil, // env
		args,
		ip, // address
		tags,
		meta,
	)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			klog.Infof("    Instance %s already exists", name)
		} else {
			return "", err
		}
	}

	return ip, nil
}
