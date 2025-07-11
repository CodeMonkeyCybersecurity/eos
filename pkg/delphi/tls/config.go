package tls

import (
	"crypto/tls"
	"os"
	"strings"
)

// GetAgentFetchTLSConfig returns TLS configuration with proper security settings for agent fetching
// Migrated from cmd/create/delphi.go getAgentFetchTLSConfig
func GetAgentFetchTLSConfig() *tls.Config {
	// ASSESS - Check environment to determine TLS settings
	// Allow insecure TLS only in development/testing environments
	insecureSkipVerify := false
	
	if env := os.Getenv("EOS_ENV"); env == "development" || env == "testing" {
		insecureSkipVerify = true
	}
	
	// Also check for explicit override
	if skip := os.Getenv("EOS_SKIP_TLS_VERIFY"); strings.ToLower(skip) == "true" {
		insecureSkipVerify = true
	}
	
	// INTERVENE - Create TLS configuration
	config := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	
	// EVALUATE - Return configured TLS settings
	return config
}