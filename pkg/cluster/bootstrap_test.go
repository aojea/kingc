package cluster

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCreateBootstrapResources(t *testing.T) {
	client := fake.NewSimpleClientset()
	token := "abcdef.0123456789abcdef"
	caCert := []byte("fake-ca-cert")
	endpoint := "https://127.0.0.1:6443"

	err := CreateBootstrapResources(context.Background(), client, token, caCert, endpoint)
	if err != nil {
		t.Fatalf("CreateBootstrapResources failed: %v", err)
	}

	// Verify Secret
	secret, err := client.CoreV1().Secrets(metav1.NamespaceSystem).Get(context.Background(), "bootstrap-token-abcdef", metav1.GetOptions{})
	if err != nil {
		t.Errorf("Secret not found: %v", err)
	}
	if string(secret.Data["token-id"]) != "abcdef" {
		t.Errorf("Expected token-id 'abcdef', got %s", secret.Data["token-id"])
	}
	if string(secret.Data["auth-extra-groups"]) != "system:bootstrappers:kubeadm:default-node-token" {
		t.Errorf("Unexpected auth-extra-groups: %s", secret.Data["auth-extra-groups"])
	}

	// Verify ConfigMap
	cm, err := client.CoreV1().ConfigMaps("kube-public").Get(context.Background(), "cluster-info", metav1.GetOptions{})
	if err != nil {
		t.Errorf("ConfigMap cluster-info not found: %v", err)
	}
	encodedCA := base64.StdEncoding.EncodeToString(caCert)
	if !strings.Contains(cm.Data["kubeconfig"], encodedCA) {
		t.Errorf("Kubeconfig does not contain CA cert (expected base64: %s)", encodedCA)
	}

	jwsKey := "jws-kubeconfig-abcdef"
	if _, ok := cm.Data[jwsKey]; !ok {
		t.Errorf("Missing JWS signature key %s", jwsKey)
	}
}

func TestParseToken(t *testing.T) {
	tests := []struct {
		token  string
		valid  bool
		id     string
		secret string
	}{
		{"abcdef.0123456789abcdef", true, "abcdef", "0123456789abcdef"},
		{"invalid", false, "", ""},
		{"too.many.dots", false, "", ""},
	}
	for _, tt := range tests {
		id, secret, err := parseToken(tt.token)
		if tt.valid && err != nil {
			t.Errorf("Expected valid parse for %s, got error: %v", tt.token, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("Expected invalid parse for %s, got nil error", tt.token)
		}
		if tt.valid {
			if id != tt.id || secret != tt.secret {
				t.Errorf("Expected %s, %s; got %s, %s", tt.id, tt.secret, id, secret)
			}
		}
	}
}
