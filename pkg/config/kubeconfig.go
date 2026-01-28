package config

import (
	"encoding/base64"
	"fmt"
)

// GenerateKubeconfig creates a kubeconfig content string
func GenerateKubeconfig(clusterName, serverURL string, caCert, clientCert, clientKey []byte) string {
	return fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: %s
contexts:
- context:
    cluster: %s
    user: kubernetes-admin
  name: kubernetes-admin@%s
current-context: kubernetes-admin@%s
kind: Config
preferences: {}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: %s
    client-key-data: %s
`,
		base64Encode(caCert),
		serverURL,
		clusterName,
		clusterName,
		clusterName,
		clusterName,
		base64Encode(clientCert),
		base64Encode(clientKey),
	)
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
