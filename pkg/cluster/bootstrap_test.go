package cluster

import (
	"bytes"
	"strings"
	"testing"
	"text/template"
)

func TestRenderBootstrapTemplate(t *testing.T) {
	// Read the template directly from the embed/fs (we need strict access to the package vars if they are private)
	// templatesFS is private in package cluster. Tests are in package cluster, so we can access it.

	tmplName := "templates/bootstrap-resources.yaml"
	tmplContent, err := templatesFS.ReadFile(tmplName)
	if err != nil {
		t.Fatalf("Failed to read template: %v", err)
	}

	funcMap := template.FuncMap{
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			return pad + strings.ReplaceAll(v, "\n", "\n"+pad)
		},
	}

	tmpl, err := template.New("bootstrap").Funcs(funcMap).Parse(string(tmplContent))
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}

	data := BootstrapData{
		TokenID:      "abcdef",
		TokenSecret:  "0123456789abcdef",
		Kubeconfig:   "apiVersion: v1\nclusters:\n- cluster:\n    server: foo",
		JWSSignature: "fake-jws",
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}

	output := buf.String()
	// Validation
	if !strings.Contains(output, "token-id: \"abcdef\"") {
		t.Errorf("Output missing token-id")
	}
	if !strings.Contains(output, "    apiVersion: v1") { // Check indentation
		t.Errorf("Indentation check failed for kubeconfig. Output:\n%s", output)
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
