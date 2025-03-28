// eos/assets/hera/createCerts.go

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// GenerateSelfSignedCerts generates a self-signed TLS cert + key into the given directory.
func GenerateSelfSignedCerts(certsDir string) error
	// Create the "certs" directory if it doesn't exist.
	certsDir := "certs"
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		fmt.Printf("Failed to create directory %s: %v\n", certsDir, err)
		os.Exit(1)
	}

	// Generate a private key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	// Create a certificate template.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Printf("Failed to generate serial number: %v\n", err)
		os.Exit(1)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Example Co"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Printf("Failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	// Write certificate to certs/tls.crt.
	certPath := filepath.Join(certsDir, "tls.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		fmt.Printf("Failed to open %s for writing: %v\n", certPath, err)
		os.Exit(1)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		fmt.Printf("Failed to write data to %s: %v\n", certPath, err)
		os.Exit(1)
	}
	fmt.Printf("Written %s\n", certPath)

	// Write private key to certs/tls.key.
	keyPath := filepath.Join(certsDir, "tls.key")
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Failed to open %s for writing: %v\n", keyPath, err)
		os.Exit(1)
	}
	defer keyOut.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		fmt.Printf("Failed to write data to %s: %v\n", keyPath, err)
		os.Exit(1)
	}
	fmt.Printf("Written %s\n", keyPath)
}
