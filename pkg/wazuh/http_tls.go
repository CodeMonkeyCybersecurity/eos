// pkg/wazuh/http_tls.go
package wazuh

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

// getHTTPTLSConfig returns TLS configuration with proper security settings for HTTP requests
func getHTTPTLSConfig() *tls.Config {
	// Allow insecure TLS only in development/testing environments
	if os.Getenv("Eos_INSECURE_TLS") == "true" || os.Getenv("GO_ENV") == "test" {
		return &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	// Secure TLS configuration for production HTTP requests
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
	}

	// SECURITY: Try to load custom CA certificate for self-signed Wazuh/OpenSearch servers
	// This supports both system-trusted CAs and custom enterprise CAs
	caPaths := []string{
		"/etc/eos/wazuh-ca.crt",       // Wazuh-specific CA
		"/etc/eos/ca.crt",             // Eos general CA
		"/etc/opensearch/tls/ca.crt",  // OpenSearch standard location
		"/etc/ssl/certs/wazuh-ca.crt", // Alternative location
	}

	for _, caPath := range caPaths {
		if _, err := os.Stat(caPath); os.IsNotExist(err) {
			continue
		}

		caCert, err := os.ReadFile(caPath)
		if err != nil {
			continue
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			continue
		}

		tlsConfig.RootCAs = caCertPool
		break // Successfully loaded CA certificate
	}

	return tlsConfig
}

// getWazuhTLSConfig is an alias for getHTTPTLSConfig for backward compatibility
func getWazuhTLSConfig() *tls.Config {
	return getHTTPTLSConfig()
}
