package cluster

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// createCACSR generates a CSR for a CA with BasicConstraints: CA:TRUE and KeyUsage: KeyCertSign|CRLSign.
func (m *Manager) createCACSR(key *rsa.PrivateKey, cn string) ([]byte, error) {
	subj := pkix.Name{
		CommonName:   cn,
		Organization: []string{"kingc"},
	}

	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	bc := basicConstraints{IsCA: true, MaxPathLen: -1}
	bcBytes, err := asn1.Marshal(bc)
	if err != nil {
		return nil, fmt.Errorf("marshal basic constraints: %v", err)
	}

	extBC := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Critical: true,
		Value:    bcBytes,
	}

	tmpl := x509.CertificateRequest{
		Subject:         subj,
		ExtraExtensions: []pkix.Extension{extBC},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}), nil
}

// SignLocalCertificate signs a leaf certificate using a local CA key/cert.
func (m *Manager) SignLocalCertificate(pubKey any, caKey *rsa.PrivateKey, caCert *x509.Certificate, cn string, orgs []string, ipSANS []net.IP, dnsSANS []string, isServer bool) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: orgs,
		},
		DNSNames:              dnsSANS,
		IPAddresses:           ipSANS,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 Year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if isServer {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, pubKey, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// ParseCertificatePEM parses a PEM-encoded certificate.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// createBootstrapToken generates a random bootstrap token and calculates the CA cert hash.
func (m *Manager) createBootstrapToken(caCert []byte) (token string, caHash string, err error) {
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

	return token, caHash, nil
}
