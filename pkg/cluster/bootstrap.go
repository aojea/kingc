package cluster

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"text/template"
)

// BootstrapData holds values for the bootstrap resources template
type BootstrapData struct {
	TokenID      string
	TokenSecret  string
	Kubeconfig   string
	JWSSignature string
}

// CreateBootstrapResources creates the Bootstrap Token Secret and cluster-info ConfigMap.
func CreateBootstrapResources(ctx context.Context, kubeconfigPath, token string, caCert []byte, endpoint string) error {
	tokenID, tokenSecret, err := parseToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %v", err)
	}

	// Generate minimal kubeconfig content for cluster-info
	// We can't use client-go here, so we'll just format it manually or use a helper
	// The cluster-info kubeconfig is very simple
	clusterInfoKubeconfig := fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: ""
contexts: []
current-context: ""
kind: Config`, base64.StdEncoding.EncodeToString(caCert), endpoint)

	// Compute JWS Signature
	jws, err := computeJWS(clusterInfoKubeconfig, token)
	if err != nil {
		return fmt.Errorf("compute jws: %v", err)
	}

	data := BootstrapData{
		TokenID:      tokenID,
		TokenSecret:  tokenSecret,
		Kubeconfig:   clusterInfoKubeconfig,
		JWSSignature: jws,
	}

	// Render the template
	tmplName := "templates/bootstrap-resources.yaml"
	tmplContent, err := templatesFS.ReadFile(tmplName)
	if err != nil {
		return fmt.Errorf("failed to read template %s: %v", tmplName, err)
	}

	funcMap := template.FuncMap{
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			return pad + strings.ReplaceAll(v, "\n", "\n"+pad)
		},
	}

	t, err := template.New("bootstrap").Funcs(funcMap).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	// Apply via kubectl
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfigPath, "apply", "-f", "-")
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply bootstrap resources: %v, output: %s", err, string(out))
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

	return b64Header + "." + b64Payload + "." + b64Signature, nil
}
