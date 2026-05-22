package cluster

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

func calculateCACertHash(caCert []byte) (string, error) {
	block, _ := pem.Decode(caCert)
	if block == nil {
		return "", fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CA cert: %v", err)
	}
	pubKeyDer, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}
	hash := sha256.Sum256(pubKeyDer)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(hash[:])), nil
}


