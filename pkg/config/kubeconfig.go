package config

import (
	"encoding/base64"
	"fmt"
)

// GenerateKubeconfig creates a kubeconfig content string
// GenerateKubeconfig creates a kubeconfig content string
func GenerateKubeconfig(clusterName, serverURL, userName string, caCert, clientCert, clientKey []byte) string {
	return fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: %s
contexts:
- context:
    cluster: %s
    user: %s
  name: %s@%s
current-context: %s@%s
kind: Config
preferences: {}
users:
- name: %s
  user:
    client-certificate-data: %s
    client-key-data: %s
`,
		base64Encode(caCert), // cluster.certificate-authority-data
		serverURL,            // cluster.server
		clusterName,          // cluster.name
		clusterName,          // context.cluster
		userName,             // context.user
		userName,             // context.name (user@cluster)
		clusterName,
		userName, // current-context (user@cluster)
		clusterName,
		userName,                 // users.name
		base64Encode(clientCert), // user.client-certificate-data
		base64Encode(clientKey),  // user.client-key-data
	)
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
