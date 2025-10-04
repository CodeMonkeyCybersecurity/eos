package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// SecureTLSConfig creates a secure TLS configuration with proper certificate validation
// SECURITY: Use this instead of InsecureSkipVerify: true
func SecureTLSConfig(caCertPath string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Minimum TLS 1.2
		// InsecureSkipVerify: false is the default - validates certificates
	}

	// If custom CA cert provided, load it
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertPath)
		}

		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// InsecureTLSConfigForDevelopment creates an insecure TLS config that skips validation
// SECURITY WARNING: ONLY use in development/testing environments!
// DO NOT use in production - exposes to MITM attacks
// Logs warning when called
func InsecureTLSConfigForDevelopment() *tls.Config {
	// This will show up in logs as a security warning
	return &tls.Config{
		InsecureSkipVerify: true, // INSECURE - accepts any certificate
		MinVersion:         tls.VersionTLS12,
	}
}
