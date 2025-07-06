// pkg/httpclient/httpclient.go

package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"time"
)

var defaultClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: getTLSConfig(),
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
}

// DefaultClient returns a preconfigured HTTP client used across Eos
func DefaultClient() *http.Client {
	return defaultClient
}

// getTLSConfig returns TLS configuration with proper security settings
func getTLSConfig() *tls.Config {
	// Allow insecure TLS only in development/testing environments
	if os.Getenv("Eos_INSECURE_TLS") == "true" || os.Getenv("GO_ENV") == "test" {
		return &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	// Secure TLS configuration for production
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
	}
}

// SetDefaultClient allows replacing the default client for testing purposes
func SetDefaultClient(client *http.Client) {
	defaultClient = client
}
