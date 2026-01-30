package cluster

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/aojea/kingc/pkg/config"

	"k8s.io/klog/v2"
)

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

	// 3. CA Hierarchy Setup (3-CA Architecture)
	// 3.1 Cluster CA (Intermediate, Ephemeral Key)
	clusterCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate cluster ca key: %v", err)
	}
	clusterCACSR, err := m.createCACSR(clusterCAKey, "cluster-ca")
	if err != nil {
		return nil, fmt.Errorf("create cluster ca csr: %v", err)
	}
	clusterCACertPEM, err := m.gce.SignCASCertificate(ctx, clusterCACSR, poolID, casRegion, caID, "P30Y")
	if err != nil {
		return nil, fmt.Errorf("sign cluster ca: %v", err)
	}
	clusterCACert, err := ParseCertificatePEM(clusterCACertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse cluster ca cert: %v", err)
	}
	// Fetch Root CA for trust bundle
	rootCAPEM, err := m.gce.GetCASRootCertificate(ctx, poolID, casRegion, caID)
	if err != nil {
		klog.Warningf("failed to fetch root ca: %v", err)
		// Fallback to just intermediate if fail? Or error?
		// generic error might block if perms missing, but we just created it.
		// Let's error.
		return nil, fmt.Errorf("fetch root ca: %v", err)
	}
	// Trust Bundle: Intermediate + Root
	trustBundlePEM := append(clusterCACertPEM, rootCAPEM...)

	// 3.2 Node CA (Intermediate, Persistent Key)
	nodeCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate node ca key: %v", err)
	}
	nodeCAKeyBytes := x509.MarshalPKCS1PrivateKey(nodeCAKey)
	nodeCAKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: nodeCAKeyBytes})

	nodeCACSR, err := m.createCACSR(nodeCAKey, "node-ca")
	if err != nil {
		return nil, fmt.Errorf("create node ca csr: %v", err)
	}
	nodeCACertPEM, err := m.gce.SignCASCertificate(ctx, nodeCACSR, poolID, casRegion, caID, "P30Y")
	if err != nil {
		return nil, fmt.Errorf("sign node ca: %v", err)
	}

	// 3.3 Front Proxy CA (Intermediate, Ephemeral Client Signing)
	fpCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate front-proxy ca key: %v", err)
	}
	fpCACSR, err := m.createCACSR(fpCAKey, "front-proxy-ca")
	if err != nil {
		return nil, fmt.Errorf("create front-proxy ca csr: %v", err)
	}
	fpCACertPEM, err := m.gce.SignCASCertificate(ctx, fpCACSR, poolID, casRegion, caID, "P30Y")
	if err != nil {
		return nil, fmt.Errorf("sign front-proxy ca: %v", err)
	}
	fpCACert, err := ParseCertificatePEM(fpCACertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse front-proxy ca cert: %v", err)
	}

	// 4. Leaf Certificates
	// 4.1 API Server Serving Cert (Signed by Cluster CA)
	apiServerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate apiserver key: %v", err)
	}
	apiServerKeyBytes := x509.MarshalPKCS1PrivateKey(apiServerKey)
	apiServerKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: apiServerKeyBytes})

	// Add SANs
	dnsNames := []string{
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local",
		"localhost",
		name,
	}
	svcPrefix, err := netip.ParsePrefix(cfg.Spec.Kubernetes.Networking.ServiceCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service cidr: %v", err)
	}
	svcIP := svcPrefix.Addr().Next()
	ips := []net.IP{
		net.ParseIP(ip),
		net.ParseIP("127.0.0.1"),
		net.ParseIP(svcIP.String()),
	}

	apiServerCertPEM, err := m.SignLocalCertificate(
		apiServerKey.Public(),
		clusterCAKey, clusterCACert,
		"kube-apiserver",
		[]string{"kingc"},
		ips, dnsNames,
		true, // isServer
	)
	if err != nil {
		return nil, fmt.Errorf("sign apiserver cert: %v", err)
	}

	// 4.2 Front Proxy Client Cert (Signed by Front Proxy CA)
	fpClientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate front-proxy client key: %v", err)
	}
	fpClientKeyBytes := x509.MarshalPKCS1PrivateKey(fpClientKey)
	fpClientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: fpClientKeyBytes})

	fpClientCertPEM, err := m.SignLocalCertificate(
		fpClientKey.Public(),
		fpCAKey, fpCACert,
		"front-proxy-client",
		nil,
		nil, nil, false,
	)
	if err != nil {
		return nil, fmt.Errorf("sign front-proxy client cert: %v", err)
	}

	// 5. Service Account Keys (Local)
	saPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate sa key: %v", err)
	}
	saKeyBytes := x509.MarshalPKCS1PrivateKey(saPrivKey)
	saKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: saKeyBytes})

	saPubKeyBytes, err := x509.MarshalPKIXPublicKey(&saPrivKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal sa public key: %v", err)
	}
	saPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: saPubKeyBytes})

	// 6. Generate Kubeconfigs (Signed by Cluster CA)
	// 6.1 Admin
	adminClientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate admin key: %v", err)
	}
	adminClientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(adminClientKey)})
	adminClientCertPEM, err := m.SignLocalCertificate(adminClientKey.Public(), clusterCAKey, clusterCACert, "kubernetes-admin", []string{"system:masters"}, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("sign admin cert: %v", err)
	}
	adminKC := config.GenerateKubeconfig(cfg.Metadata.Name, fmt.Sprintf("https://%s", net.JoinHostPort(ip, "6443")),
		"kubernetes-admin", trustBundlePEM, adminClientCertPEM, adminClientKeyPEM)

	// 6.2 Scheduler
	schedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate scheduler key: %v", err)
	}
	schedKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(schedKey)})
	schedCertPEM, err := m.SignLocalCertificate(schedKey.Public(), clusterCAKey, clusterCACert, "system:kube-scheduler", []string{"system:kube-scheduler"}, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("sign scheduler cert: %v", err)
	}
	schedKC := config.GenerateKubeconfig(cfg.Metadata.Name, fmt.Sprintf("https://%s", net.JoinHostPort(ip, "6443")),
		"system:kube-scheduler", trustBundlePEM, schedCertPEM, schedKeyPEM)

	// 6.3 Controller Manager
	cmKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate cm key: %v", err)
	}
	cmKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cmKey)})
	cmCertPEM, err := m.SignLocalCertificate(cmKey.Public(), clusterCAKey, clusterCACert, "system:kube-controller-manager", []string{"system:kube-controller-manager"}, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("sign cm cert: %v", err)
	}
	cmKC := config.GenerateKubeconfig(cfg.Metadata.Name, fmt.Sprintf("https://%s", net.JoinHostPort(ip, "6443")),
		"system:kube-controller-manager", trustBundlePEM, cmCertPEM, cmKeyPEM)

	// 7. Embed startup script
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
echo "%s" > /var/lib/kingc/pki/run-ca.crt
echo "%s" >> /var/lib/kingc/pki/run-ca.crt
mv /var/lib/kingc/pki/run-ca.crt /var/lib/kingc/pki/ca.crt
echo "%s" > /var/lib/kingc/pki/sa.pub
echo "%s" > /var/lib/kingc/pki/sa.key
echo "%s" > /var/lib/kingc/pki/front-proxy-ca.crt
echo "%s" > /var/lib/kingc/pki/front-proxy-client.crt
echo "%s" > /var/lib/kingc/pki/front-proxy-client.key
`,
		string(apiServerKeyPEM), string(apiServerCertPEM),
		string(clusterCACertPEM), string(nodeCACertPEM),
		string(saPubPEM), string(saKeyPEM),
		string(fpCACertPEM),
		string(fpClientCertPEM), string(fpClientKeyPEM),
	)

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

	if cfg.Spec.Kubernetes.OIDC != nil {
		args = append(args,
			"--oidc-issuer-url="+cfg.Spec.Kubernetes.OIDC.IssuerURL,
			"--oidc-client-id="+cfg.Spec.Kubernetes.OIDC.ClientID,
			"--oidc-username-claim="+cfg.Spec.Kubernetes.OIDC.UsernameClaim,
		)
		if cfg.Spec.Kubernetes.OIDC.GroupsClaim != "" {
			args = append(args, "--oidc-groups-claim="+cfg.Spec.Kubernetes.OIDC.GroupsClaim)
		}
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
	// Extract leaf for SigningCert (KCM expects single cert)
	nodeCALeafPEM := nodeCACertPEM
	if block, _ := pem.Decode(nodeCACertPEM); block != nil {
		nodeCALeafPEM = pem.EncodeToMemory(block)
	}

	return &ExternalAPIServerResult{
		Endpoint: ip,
		// Bundle: Trust Bundle (Cluster+Root) + Node CA
		CACert:                      append(trustBundlePEM, nodeCACertPEM...),
		SigningKey:                  nodeCAKeyPEM,
		SigningCert:                 nodeCALeafPEM, // Single Cert for KCM
		SAKey:                       saKeyPEM,
		SAPub:                       saPubPEM,
		FrontProxyCACert:            fpCACertPEM,
		AdminKubeconfig:             adminKC,
		SchedulerKubeconfig:         schedKC,
		ControllerManagerKubeconfig: cmKC,
	}, nil
}
