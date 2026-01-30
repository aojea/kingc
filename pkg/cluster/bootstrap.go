package cluster

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// CreateBootstrapResources creates the Bootstrap Token Secret and cluster-info ConfigMap.
func CreateBootstrapResources(ctx context.Context, client kubernetes.Interface, token string, caCert []byte, endpoint string) error {
	tokenID, tokenSecret, err := parseToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %v", err)
	}

	// 1. Create Bootstrap Token Secret
	if err := createBootstrapTokenSecret(ctx, client, tokenID, tokenSecret); err != nil {
		return fmt.Errorf("failed to create bootstrap token secret: %v", err)
	}

	// 2. Create/Update cluster-info ConfigMap
	if err := createClusterInfo(ctx, client, tokenID, token, caCert, endpoint); err != nil {
		return fmt.Errorf("failed to create cluster-info: %v", err)
	}

	// 3. Create RBAC Roles/Bindings for Bootstrapping
	if err := CreateBootstrapRBAC(ctx, client); err != nil {
		return fmt.Errorf("failed to create bootstrap rbac: %v", err)
	}

	return nil
}

func parseToken(token string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("token must be in format 'abcdef.0123456789abcdef'")
	}
	return parts[0], parts[1], nil
}

func createBootstrapTokenSecret(ctx context.Context, client kubernetes.Interface, tokenID, tokenSecret string) error {
	secretName := fmt.Sprintf("bootstrap-token-%s", tokenID)
	data := map[string][]byte{
		"token-id":                       []byte(tokenID),
		"token-secret":                   []byte(tokenSecret),
		"usage-bootstrap-authentication": []byte("true"),
		"usage-bootstrap-signing":        []byte("true"),
		"auth-extra-groups":              []byte("system:bootstrappers:kubeadm:default-node-token"),
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: metav1.NamespaceSystem,
		},
		Type: corev1.SecretTypeBootstrapToken,
		Data: data,
	}

	_, err := client.CoreV1().Secrets(metav1.NamespaceSystem).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			_, err = client.CoreV1().Secrets(metav1.NamespaceSystem).Update(ctx, secret, metav1.UpdateOptions{})
		}
	}
	return err
}

func createClusterInfo(ctx context.Context, client kubernetes.Interface, tokenID, token string, caCert []byte, endpoint string) error {
	// Generate minimal kubeconfig
	kubeconfig := api.Config{
		Clusters: map[string]*api.Cluster{
			"": {
				Server:                   endpoint,
				CertificateAuthorityData: caCert,
			},
		},
	}

	configBytes, err := clientcmd.Write(kubeconfig)
	if err != nil {
		return fmt.Errorf("check kubeconfig encoding: %v", err)
	}

	// Generate JWS Signature
	// JWS = BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
	// Here payload is the kubeconfig content
	// Header = {"alg":"HS256"}

	jws, err := computeJWS(string(configBytes), token)
	if err != nil {
		return fmt.Errorf("compute jws: %v", err)
	}

	cmName := "cluster-info"
	cmNamespace := "kube-public"

	// Check if exists
	cm, err := client.CoreV1().ConfigMaps(cmNamespace).Get(ctx, cmName, metav1.GetOptions{})
	exists := err == nil

	if !exists {
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: cmNamespace,
			},
			Data: map[string]string{
				"kubeconfig": string(configBytes),
			},
		}
	} else {
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data["kubeconfig"] = string(configBytes)
	}

	// Add JWS signature
	key := fmt.Sprintf("jws-kubeconfig-%s", tokenID)
	cm.Data[key] = jws

	if !exists {
		_, err = client.CoreV1().ConfigMaps(cmNamespace).Create(ctx, cm, metav1.CreateOptions{})
		// Handle potential race if created concurrently
		if err != nil && strings.Contains(err.Error(), "already exists") {
			return createClusterInfo(ctx, client, tokenID, token, caCert, endpoint) // Retry via update path
		}
		return err
	}

	// Update
	_, err = client.CoreV1().ConfigMaps(cmNamespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// computeJWS computes the detached JWS signature for the given payload using the secret (token).
// https://tools.ietf.org/html/rfc7515
func computeJWS(payload, secret string) (string, error) {
	header := `{"alg":"HS256"}`
	b64Header := base64.RawURLEncoding.EncodeToString([]byte(header))
	b64Payload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	signingInput := b64Header + "." + b64Payload

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	b64Signature := base64.RawURLEncoding.EncodeToString(signature)

	// Kubernetes bootstrap tokens usage of JWS for cluster-info seems to contain full JWS?
	// The docs say "A JWS signature of the content of the kubeconfig field"
	// Looking at kubeadm implementation:
	// It stores the FULL JWS string.

	return b64Header + "." + b64Payload + "." + b64Signature, nil
}

// CreateBootstrapRBAC creates the necessary ClusterRoles and Bindings for kubelet bootstrapping.
func CreateBootstrapRBAC(ctx context.Context, client kubernetes.Interface) error {
	groupName := "system:bootstrappers:kubeadm:default-node-token"

	// 1. ClusterRoleBinding: Allow bootstrapping (CSR creation)
	// Binds group to system:node-bootstrapper
	crbBootstrap := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "kingc:kubelet-bootstrap"},
		Subjects: []rbacv1.Subject{
			{Kind: "Group", Name: groupName, APIGroup: "rbac.authorization.k8s.io"},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:node-bootstrapper",
		},
	}
	if _, err := client.RbacV1().ClusterRoleBindings().Create(ctx, crbBootstrap, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	// 2. ClusterRoleBinding: Auto-approve node client CSRs
	// Binds group to system:certificates.k8s.io:certificatesigningrequests:nodeclient
	crbAutoApprove := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "kingc:node-autoapprove-bootstrap"},
		Subjects: []rbacv1.Subject{
			{Kind: "Group", Name: groupName, APIGroup: "rbac.authorization.k8s.io"},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
		},
	}
	if _, err := client.RbacV1().ClusterRoleBindings().Create(ctx, crbAutoApprove, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	// 3. ClusterRole + Binding: Allow getting nodes (kubeadm pre-check)
	// Some versions of kubeadm/kubelet check if the node exists.
	roleGetNodes := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "kingc:get-nodes"},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{""},
				Resources: []string{"nodes"},
			},
		},
	}
	if _, err := client.RbacV1().ClusterRoles().Create(ctx, roleGetNodes, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	crbGetNodes := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "kingc:get-nodes"},
		Subjects: []rbacv1.Subject{
			{Kind: "Group", Name: groupName, APIGroup: "rbac.authorization.k8s.io"},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "kingc:get-nodes",
		},
	}
	if _, err := client.RbacV1().ClusterRoleBindings().Create(ctx, crbGetNodes, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	return nil
}
