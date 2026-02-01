package cluster

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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

type ExternalAPIServerResult struct {
	Endpoint    string
	CACert      []byte
	SigningKey  []byte // New: For KCM CSR Signing
	SigningCert []byte // New: For KCM CSR Signing
	SAKey       []byte
	SAPub       []byte
	Kubeconfig  string
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
	var caCert, saPub, signingKey, signingCert []byte
	var localKubeconfig string
	var adminKubeconfig, schedulerKubeconfig, cmKubeconfig string

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

		res, err := m.EnsureExternalAPIServer(ctx, cfg, zone, netName, subName)
		if err != nil {
			return fmt.Errorf("failed to ensure external apiserver: %v", err)
		}
		// Parse the endpoint IP into a URL
		u, err := url.Parse(fmt.Sprintf("https://%s", net.JoinHostPort(res.Endpoint, "6443")))
		if err != nil {
			return fmt.Errorf("failed to parse external apiserver url: %v", err)
		}
		cfg.Spec.ExternalAPIServer = u

		// Generate Admin Kubeconfig locally
		{
			klog.Infof("  > Generating local kubeconfigs...")

			// 1. Admin
			adminKubeconfig, err = m.signKubeconfig(ctx, cfg, "kubernetes-admin", []string{"system:masters"}, res.CACert)
			if err != nil {
				return fmt.Errorf("signing admin kubeconfig: %v", err)
			}
			localKubeconfig = filepath.Join(tmpDir, "admin.conf")
			if err := os.WriteFile(localKubeconfig, []byte(adminKubeconfig), 0600); err != nil {
				return fmt.Errorf("failed to write kubeconfig to %s: %v", localKubeconfig, err)
			}
			klog.Infof("    ✅ Admin Kubeconfig generated locally at %s", localKubeconfig)

			// 2. Scheduler
			schedulerKubeconfig, err = m.signKubeconfig(ctx, cfg, "system:kube-scheduler", []string{"system:kube-scheduler"}, res.CACert)
			if err != nil {
				return fmt.Errorf("signing scheduler kubeconfig: %v", err)
			}

			// 3. Controller Manager
			cmKubeconfig, err = m.signKubeconfig(ctx, cfg, "system:kube-controller-manager", []string{"system:kube-controller-manager"}, res.CACert)
			if err != nil {
				return fmt.Errorf("signing controller-manager kubeconfig: %v", err)
			}
		}

		// Store PKI data for Control Plane provisioning
		caCert = res.CACert
		saPub = res.SAPub
		// Signing CA for KCM
		// We'll write these to the CP node
		signingKey = res.SigningKey
		signingCert = res.SigningCert
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
		"ClusterName":                 cfg.Metadata.Name,
		"ControlPlaneEndpoint":        cfg.Spec.ExternalAPIServer.Host,
		"ControlPlaneIP":              cfg.Spec.ExternalAPIServer.Hostname(),
		"KubernetesVersion":           cfg.Spec.Kubernetes.Version,
		"KubernetesRepoVersion":       repoVer,
		"PodSubnet":                   cfg.Spec.Kubernetes.Networking.PodCIDR,
		"ServiceSubnet":               cfg.Spec.Kubernetes.Networking.ServiceCIDR,
		"KindnetImage":                "registry.k8s.io/networking/kindnet:v1.0.0",
		"CCMImage":                    "registry.k8s.io/cloud-provider-gcp/cloud-controller-manager:v35.0.0",
		"FeatureGates":                cfg.Spec.FeatureGates,
		"RuntimeConfig":               rcBuilder.String(),
		"Kubeconfig":                  adminKubeconfig,
		"SchedulerKubeconfig":         schedulerKubeconfig,
		"ControllerManagerKubeconfig": cmKubeconfig,
	}

	// Render the base installation script
	baseInstallScript, err := m.renderTemplate("templates/startup.sh", templateData)
	if err != nil {
		return err
	}

	// 3.5 Create Bootstrap Token (Early)
	var bootstrapToken, caHash string
	{
		klog.Infof("  > Creating Bootstrap Token...")
		bootstrapToken, caHash, err = m.createBootstrapToken(ctx, localKubeconfig, caCert)
		if err != nil {
			return fmt.Errorf("create bootstrap token: %v", err)
		}
		// Add to template data
		templateData["BootstrapToken"] = bootstrapToken
		templateData["DiscoveryTokenCaCertHash"] = caHash
	}

	// 4. Prepare Control Plane Config & Script
	klog.Infof("  > Generating Kubeadm Join config for Control Plane...")
	// We use JoinConfiguration now
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
	// We run kubeadm join (worker mode) but with CP labels/taints
	kubeadmArgs := "--ignore-preflight-errors=NumCPU"

	cpStartupScript := fmt.Sprintf(`%s

# ---------------------------------------------------------
# Control Plane Bootstrap
# ---------------------------------------------------------
echo "👑 kingc: Writing PKI files (SA Keys & Signing CA)..."
mkdir -p /etc/kubernetes/pki
# CA Cert will be fetched by kubeadm join, but we can pre-populate if we want.
# However, SA keys are NOT fetched by worker join, so we MUST provide them for CM.
echo "%s" > /etc/kubernetes/pki/sa.pub

# Signing CA for KCM (CSR Signing)
echo "%s" > /etc/kubernetes/pki/signing-ca.key
echo "%s" > /etc/kubernetes/pki/signing-ca.crt

echo "👑 kingc: Writing Kubeconfigs..."
echo "%s" > /etc/kubernetes/admin.conf
echo "%s" > /etc/kubernetes/scheduler.conf
echo "%s" > /etc/kubernetes/controller-manager.conf

echo "👑 kingc: Writing kubeadm config..."
mkdir -p /etc/kubernetes
cat <<EOF > /etc/kubernetes/kubeadm-config.yaml
%s
EOF

ARGS="%s"
echo "👑 kingc: Joining Control Plane Node..."
kubeadm join --config /etc/kubernetes/kubeadm-config.yaml $ARGS

echo "👑 kingc: Control Plane Joined"
`, baseInstallScript, string(saPub), string(signingKey), string(signingCert), templateData["Kubeconfig"], templateData["SchedulerKubeconfig"], templateData["ControllerManagerKubeconfig"], kubeadmConfig, kubeadmArgs)

	tmpCPStartup := filepath.Join(tmpDir, "cp-startup.sh")
	if err := os.WriteFile(tmpCPStartup, []byte(cpStartupScript), 0644); err != nil {
		return fmt.Errorf("failed to write startup script: %v", err)
	}

	// 4.5 Apply Control Plane Manifests (Scheduler, Controller Manager)
	{
		defer m.measure("Apply CP Manifests")()
		klog.Infof("  > Applying Control Plane Manifests...")

		manifests := []string{"kube-scheduler.yaml", "kube-controller-manager.yaml"}
		for _, man := range manifests {
			out, err := m.renderTemplate("templates/"+man, templateData)
			if err != nil {
				return err
			}
			tmpMan := filepath.Join(tmpDir, man)
			if err := os.WriteFile(tmpMan, []byte(out), 0644); err != nil {
				return err
			}
			cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", localKubeconfig, "apply", "-f", tmpMan)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to apply %s: %v, output: %s", man, err, out)
			}
			klog.Infof("    ✅ Applied %s", man)
		}
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

	// 9. Worker Pools
	{
		defer m.measure("Worker Groups Provisioning")()
		klog.Infof("  > Provisioning Worker Groups...")

		// Generate Join Command locally (reusing existing token info)
		// joinCommand is like "kubeadm join host:port --token ... --discovery-token-ca-cert-hash ..."
		joinCommand := fmt.Sprintf("kubeadm join %s --token %s --discovery-token-ca-cert-hash %s", cfg.Spec.ExternalAPIServer.Host, bootstrapToken, caHash)

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

	// Delete Instance Templates
	{
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

func (m *Manager) EnsureExternalAPIServer(ctx context.Context, cfg *config.Cluster, zone, network, subnet string) (*ExternalAPIServerResult, error) {
	name := fmt.Sprintf("%s-apiserver", basename(cfg.Metadata.Name))

	// Assume image is in the current project's GCR
	image := config.DefaultAPIServerImage

	klog.Infof("  > Ensuring External APIServer instance %s (Image: %s)...", name, image)

	// Check if already exists
	ip, err := m.gce.EnsureStaticIP(ctx, name, cfg.Spec.Region)
	if err != nil {
		return nil, err
	}

	// --- PKI Setup with Google CAS ---
	klog.Infof("  > Configuring Public Key Infrastructure (Google CAS)...")
	casRegion := cfg.Spec.Region // Use same region for CAS
	poolID := fmt.Sprintf("kingc-pool-%s", cfg.Metadata.Name)
	caID := fmt.Sprintf("kingc-ca-%s", cfg.Metadata.Name)

	// 1. Ensure Pool
	if err := m.gce.CreateCASPool(ctx, poolID, casRegion); err != nil {
		return nil, fmt.Errorf("failed to create CAS pool: %v", err)
	}
	// 2. Ensure Root CA
	if err := m.gce.CreateCASRootCA(ctx, poolID, casRegion, caID, "kingc-ca"); err != nil {
		return nil, fmt.Errorf("failed to create CAS Root CA: %v", err)
	}

	// 3. Generate CSR for API Server
	// Generate local key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key: %v", err)
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
		return nil, fmt.Errorf("failed to parse service cidr: %v", err)
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
		return nil, fmt.Errorf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// 4. Sign CSR
	// We need to use "gcloud privateca certificates create"
	certPEM, err := m.gce.SignCASCertificate(ctx, csrPEM, poolID, casRegion, caID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %v", err)
	}

	// 4.5 Get Root CA
	caPEM, err := m.gce.GetCASRootCertificate(ctx, poolID, casRegion, caID)
	if err != nil {
		return nil, fmt.Errorf("failed to get root CA: %v", err)
	}

	// 5. Setup Service Account Keys
	// CAS is not used for SA keys (JWT signing), so we generate them locally.
	// We generate them here ensuring the Manager is the source of truth.
	saPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sa key: %v", err)
	}
	saKeyBytes := x509.MarshalPKCS1PrivateKey(saPrivKey)
	saKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: saKeyBytes})

	saPubKeyBytes, err := x509.MarshalPKIXPublicKey(&saPrivKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sa public key: %v", err)
	}
	saPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: saPubKeyBytes})

	// 5.5 Front Proxy PKI
	// 5.5.1 Generate Front Proxy CA (Delegated Intermediate)
	fpCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate front-proxy ca key: %v", err)
	}
	fpCAKeyBytes := x509.MarshalPKCS1PrivateKey(fpCAKey)
	fpCAKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: fpCAKeyBytes})

	fpCATmpl := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "front-proxy-ca"},
	}
	fpCACSRBytes, err := x509.CreateCertificateRequest(rand.Reader, &fpCATmpl, fpCAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create front-proxy ca csr: %v", err)
	}
	fpCACSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: fpCACSRBytes})

	// Sign Front Proxy CA with CAS (isCA=true)
	fpCACertPEM, err := m.gce.SignCASCertificate(ctx, fpCACSRPEM, poolID, casRegion, caID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to sign front-proxy ca cert: %v", err)
	}

	// 5.5.2 Generate Front Proxy Client Cert (Signed by Local Front Proxy CA)
	fpClientKey, fpClientCertPEM, err := m.generateSignedCert(fpCAKeyPEM, fpCACertPEM, "front-proxy-client", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate front-proxy client cert: %v", err)
	}
	// Decode Client Key for startup script (generateSignedCert returns PEM)
	fpClientKeyPEM := fpClientKey

	// 5.6 Cluster Signing CA (Local, for KCM CSR Signing)
	// We generate this locally because KCM needs the private key to sign CSRs.
	// CAS keys are not exportable.
	signCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing ca key: %v", err)
	}
	signCAKeyBytes := x509.MarshalPKCS1PrivateKey(signCAKey)
	signCAKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: signCAKeyBytes})

	signCATmpl := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "cluster-signing-ca"},
	}
	signCACSRBytes, err := x509.CreateCertificateRequest(rand.Reader, &signCATmpl, signCAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing ca csr: %v", err)
	}
	signCACSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: signCACSRBytes})

	// Sign Signing CA with CAS (isCA=true) -> Intermediate CA
	signCACertPEM, err := m.gce.SignCASCertificate(ctx, signCACSRPEM, poolID, casRegion, caID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to sign signing ca cert: %v", err)
	}

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
	// Note: We append signing-ca.crt to ca.crt (Trust Bundle)
	// The API Server needs to trust certificates issued by this Signing CA.
	startupScript += fmt.Sprintf(`
echo "%s" > /var/lib/kingc/pki/apiserver.key
echo "%s" > /var/lib/kingc/pki/apiserver.crt
echo "%s" > /var/lib/kingc/pki/run-ca.crt
echo "%s" >> /var/lib/kingc/pki/run-ca.crt
mv /var/lib/kingc/pki/run-ca.crt /var/lib/kingc/pki/ca.crt
echo "%s" > /var/lib/kingc/pki/sa.pub
echo "%s" > /var/lib/kingc/pki/front-proxy-ca.key
echo "%s" > /var/lib/kingc/pki/front-proxy-ca.crt
echo "%s" > /var/lib/kingc/pki/front-proxy-client.crt
echo "%s" > /var/lib/kingc/pki/front-proxy-client.key
`, string(keyPEM), string(certPEM), string(caPEM), string(signCACertPEM), string(saPubPEM), string(fpCAKeyPEM), string(fpCACertPEM), string(fpClientCertPEM), string(fpClientKeyPEM))

	args := []string{
		"--secure-port=6443",
		"--service-cluster-ip-range=" + cfg.Spec.Kubernetes.Networking.ServiceCIDR,
		"--service-account-key-file=/var/run/kubernetes/sa.pub",
		"--service-account-signing-key-file=/var/run/kubernetes/sa.key",
		"--service-account-issuer=https://kubernetes.default.svc.cluster.local",
		"--authorization-mode=Node,RBAC",
		"--advertise-address=" + ip,
		"--tls-cert-file=/var/run/kubernetes/apiserver.crt",
		"--tls-private-key-file=/var/run/kubernetes/apiserver.key",
		"--client-ca-file=/var/run/kubernetes/ca.crt",
		"--allow-privileged=true",
		"--enable-admission-plugins=NodeRestriction",
		"--enable-bootstrap-token-auth=true",
		"--requestheader-client-ca-file=/var/run/kubernetes/front-proxy-ca.crt",
		"--requestheader-allowed-names=front-proxy-client",
		"--requestheader-extra-headers-prefix=X-Remote-Extra-",
		"--requestheader-group-headers=X-Remote-Group",
		"--requestheader-username-headers=X-Remote-User",
		"--proxy-client-cert-file=/var/run/kubernetes/front-proxy-client.crt",
		"--proxy-client-key-file=/var/run/kubernetes/front-proxy-client.key",
		"--v=2",
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
			return nil, err
		}
	}

	return &ExternalAPIServerResult{
		Endpoint:    ip,
		CACert:      caPEM,
		SigningKey:  signCAKeyPEM,
		SigningCert: signCACertPEM,
		SAKey:       saKeyPEM,
		SAPub:       saPubPEM,
	}, nil
}

func (m *Manager) signKubeconfig(ctx context.Context, cfg *config.Cluster, cn string, orgs []string, caCert []byte) (string, error) {
	// Generate Key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("generate key: %v", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	// CSR
	subj := pkix.Name{
		CommonName:   cn,
		Organization: orgs,
	}
	template := x509.CertificateRequest{
		Subject: subj,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return "", fmt.Errorf("create csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// Sign with CAS
	poolID := fmt.Sprintf("kingc-pool-%s", cfg.Metadata.Name)
	caID := fmt.Sprintf("kingc-ca-%s", cfg.Metadata.Name)
	casRegion := cfg.Spec.Region

	// isCA=false for Client Certs
	certPEM, err := m.gce.SignCASCertificate(ctx, csrPEM, poolID, casRegion, caID, false)
	if err != nil {
		return "", fmt.Errorf("sign certificate: %v", err)
	}

	// Generate Kubeconfig
	return config.GenerateKubeconfig(
		cfg.Metadata.Name,
		cfg.Spec.ExternalAPIServer.String(),
		cn,
		caCert,
		certPEM,
		keyPEM,
	), nil
}

func (m *Manager) createBootstrapToken(ctx context.Context, kubeconfigPath string, caCert []byte) (token string, caHash string, err error) {
	// 1. Calculate CA Cert Hash (Discovery Token CA Cert Hash)
	// openssl x509 -in ca.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
	// Go: sha256(SubjectPublicKeyInfo)
	block, _ := pem.Decode(caCert)
	if block == nil {
		return "", "", fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse CA cert: %v", err)
	}
	pubKeyDer, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %v", err)
	}
	hash := sha256.Sum256(pubKeyDer)
	caHash = fmt.Sprintf("sha256:%s", hex.EncodeToString(hash[:]))

	// 2. Create Bootstrap Token
	// ID: 6 chars, Secret: 16 chars (hex/alphanum? [a-z0-9])
	// kubeadm uses random lowercase alphanum
	tokenID := randString(6)
	tokenSecret := randString(16)
	token = fmt.Sprintf("%s.%s", tokenID, tokenSecret)

	// Create Secret in kube-system
	// We use text/template or just fmt.Sprintf for the Secret manifest
	secretName := fmt.Sprintf("bootstrap-token-%s", tokenID)
	// Expiration: 24h
	expiration := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	secretYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: kube-system
type: bootstrap.kubernetes.io/token
stringData:
  token-id: "%s"
  token-secret: "%s"
  usage-bootstrap-authentication: "true"
  usage-bootstrap-signing: "true"
  expiration: "%s"
`, secretName, tokenID, tokenSecret, expiration)

	tmpSecret := filepath.Join(filepath.Dir(kubeconfigPath), "bootstrap-token.yaml")
	if err := os.WriteFile(tmpSecret, []byte(secretYAML), 0644); err != nil {
		return "", "", err
	}

	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfigPath, "apply", "-f", tmpSecret)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("failed to create bootstrap token: %v, out: %s", err, out)
	}

	return token, caHash, nil
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "abcdef"
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func (m *Manager) generateSignedCert(caKeyPEM, caCertPEM []byte, cn string, orgs []string) (keyPEM, certPEM []byte, err error) {
	// Parse CA
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode ca cert")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %v", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode ca key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %v", err)
	}

	// Generate Key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %v", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	// Cert Template
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2), // Randomize?
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: orgs,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * 365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return keyPEM, certPEM, nil
}
