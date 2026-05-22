package cluster

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCalculateCACertHash(t *testing.T) {
	// 1. Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// 2. Create simple self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// 3. Call calculateCACertHash
	hash, err := calculateCACertHash(certPEM)
	if err != nil {
		t.Fatalf("failed to calculate CA cert hash: %v", err)
	}

	// 4. Basic sanity checks
	if len(hash) == 0 {
		t.Errorf("expected non-empty hash")
	}
	const expectedPrefix = "sha256:"
	if len(hash) <= len(expectedPrefix) || hash[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("expected hash to start with %q, got %q", expectedPrefix, hash)
	}

	// Test invalid PEM
	_, err = calculateCACertHash([]byte("invalid-pem-data"))
	if err == nil {
		t.Errorf("expected error for invalid PEM data, got nil")
	}
}
