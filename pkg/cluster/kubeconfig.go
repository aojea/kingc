package cluster

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"
)

// mergeKubeconfig merges the new cluster configuration into the user's default KUBECONFIG.
// It renames the context, cluster, and user to avoid collisions (e.g., "kubernetes-admin").
func mergeKubeconfig(clusterName string, newConfigData []byte) error {
	// 1. Load the new config
	newConfig, err := clientcmd.Load(newConfigData)
	if err != nil {
		return fmt.Errorf("failed to parse new kubeconfig: %v", err)
	}

	// 2. Rename objects in new config to be unique
	// Default kubeadm config uses:
	//   Cluster: "kubernetes"
	//   User: "kubernetes-admin"
	//   Context: "kubernetes-admin@kubernetes"
	// We want:
	//   Cluster: "kingc-<name>"
	//   User: "kingc-<name>-admin"
	//   Context: "kingc-<name>"

	uniqueClusterName := fmt.Sprintf("kingc-%s", clusterName)
	uniqueUserName := fmt.Sprintf("kingc-%s-admin", clusterName)
	uniqueContextName := uniqueClusterName

	// Update Clusters
	for oldName, cluster := range newConfig.Clusters {
		delete(newConfig.Clusters, oldName)
		newConfig.Clusters[uniqueClusterName] = cluster
	}

	// Update AuthInfos (Users)
	for oldName, authInfo := range newConfig.AuthInfos {
		delete(newConfig.AuthInfos, oldName)
		newConfig.AuthInfos[uniqueUserName] = authInfo
	}

	// Update Contexts
	for oldName, ctx := range newConfig.Contexts {
		delete(newConfig.Contexts, oldName)
		ctx.Cluster = uniqueClusterName
		ctx.AuthInfo = uniqueUserName
		newConfig.Contexts[uniqueContextName] = ctx
	}

	newConfig.CurrentContext = uniqueContextName

	// 3. Determine target kubeconfig file
	// Logic: Use KUBECONFIG env var (first file) or default ~/.kube/config
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	targetFile := loadingRules.GetDefaultFilename()

	// If explicit path(s) set, use the first one that exists or the first one if none exist?
	// clientcmd loading rules prioritize the first in the list for Precedence.
	// But GetDefaultFilename() might return ~/.kube/config if env is empty.
	// Let's rely on loadingRules.Precedence to find where to merge.
	// Actually, typical tools write to the first file in KUBECONFIG if set.

	if len(loadingRules.Precedence) > 0 {
		targetFile = loadingRules.Precedence[0]
	}

	klog.Infof("Merging kubeconfig into %s...", targetFile)

	// 4. Load existing config (if it exists)
	existingConfig, err := clientcmd.LoadFromFile(targetFile)
	if err != nil {
		if os.IsNotExist(err) {
			existingConfig = api.NewConfig()
		} else {
			return fmt.Errorf("failed to load existing kubeconfig from %s: %v", targetFile, err)
		}
	}

	// 5. Merge new into existing
	for k, v := range newConfig.Clusters {
		existingConfig.Clusters[k] = v
	}
	for k, v := range newConfig.AuthInfos {
		existingConfig.AuthInfos[k] = v
	}
	for k, v := range newConfig.Contexts {
		existingConfig.Contexts[k] = v
	}
	existingConfig.CurrentContext = newConfig.CurrentContext

	// 6. Write back
	// Ensure directory exists
	dir := filepath.Dir(targetFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	if err := clientcmd.WriteToFile(*existingConfig, targetFile); err != nil {
		return fmt.Errorf("failed to write merged kubeconfig: %v", err)
	}

	klog.Infof("✅ Kubeconfig merged. Switched context to %q.", uniqueContextName)
	return nil
}

// CreateBootstrapKubeconfig creates a kubeconfig used for TLS bootstrapping (token-based).
func CreateBootstrapKubeconfig(clusterName, endpoint string, caCert []byte, token string) ([]byte, error) {
	config := api.NewConfig()

	cluster := api.NewCluster()
	cluster.Server = endpoint
	cluster.CertificateAuthorityData = caCert
	config.Clusters[clusterName] = cluster

	authInfo := api.NewAuthInfo()
	authInfo.Token = token
	userName := "tls-bootstrap-token-user"
	config.AuthInfos[userName] = authInfo

	context := api.NewContext()
	context.Cluster = clusterName
	context.AuthInfo = userName
	config.Contexts[clusterName] = context
	config.CurrentContext = clusterName

	return clientcmd.Write(*config)
}
