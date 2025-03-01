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
	"time"
)

func main() {
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

	// Write certificate to tls.crt.
	certOut, err := os.Create("tls.crt")
	if err != nil {
		fmt.Printf("Failed to open tls.crt for writing: %v\n", err)
		os.Exit(1)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		fmt.Printf("Failed to write data to tls.crt: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Written tls.crt")

	// Write private key to tls.key.
	keyOut, err := os.OpenFile("tls.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Failed to open tls.key for writing: %v\n", err)
		os.Exit(1)
	}
	defer keyOut.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		fmt.Printf("Failed to write data to tls.key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Written tls.key")
}
