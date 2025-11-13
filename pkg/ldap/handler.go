/* pkg/ldap/handler.go */

package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/go-ldap/ldap/v3"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Connect returns a default LDAP connection using autodiscovered config
func Connect(rc *eos_io.RuntimeContext) (*ldap.Conn, error) {
	conn, _, err := ConnectWithConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("Connect() failed: %w", err)
	}
	return conn, nil
}

// ConnectWithConfig tries all discovery methods to return an active LDAP connection
func ConnectWithConfig(rc *eos_io.RuntimeContext) (*ldap.Conn, *LDAPConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	cfg, source, err := ReadConfig(rc)
	if err != nil {
		return nil, nil, fmt.Errorf("could not load LDAP config: %w", err)
	}

	logger.Info("Connecting to LDAP",
		zap.String("source", source),
		zap.String("fqdn", cfg.FQDN),
		zap.Int("port", cfg.Port))

	addr := fmt.Sprintf("ldap://%s:%d", cfg.FQDN, cfg.Port)
	var conn *ldap.Conn

	if cfg.UseTLS {
		addr = fmt.Sprintf("ldaps://%s:%d", cfg.FQDN, cfg.Port)
		tlsConfig := getSecureTLSConfig()
		conn, err = ldap.DialURL(addr, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(addr)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to LDAP at %s: %w", addr, err)
	}

	err = conn.Bind(cfg.BindDN, cfg.Password)
	if err != nil {
		// Check the error return from conn.Close() when binding fails.
		if cerr := conn.Close(); cerr != nil {
			logger.Warn("Failed to close LDAP connection after bind failure", zap.Error(cerr))
		}
		return nil, nil, fmt.Errorf("failed to bind to LDAP as %s: %w", cfg.BindDN, err)
	}

	logger.Info("Connected and bound to LDAP successfully",
		zap.String("bind_dn", cfg.BindDN))
	return conn, cfg, nil
}

// getSecureTLSConfig returns TLS configuration with proper security settings for LDAP
func getSecureTLSConfig() *tls.Config {
	// Allow insecure TLS only in development/testing environments
	if os.Getenv("Eos_INSECURE_TLS") == "true" || os.Getenv("GO_ENV") == "test" {
		return &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	// Secure TLS configuration for production LDAP connections
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

	// SECURITY: Try to load custom CA certificate for self-signed LDAP servers
	// This supports both system-trusted CAs and custom enterprise CAs
	caPaths := []string{
		"/etc/eos/ldap-ca.crt",       // Eos LDAP-specific CA
		"/etc/eos/ca.crt",            // Eos general CA
		"/etc/ldap/tls/ca.crt",       // LDAP standard location
		"/etc/ssl/certs/ldap-ca.crt", // Alternative location
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

func ConnectWithGivenConfig(cfg *LDAPConfig) (*ldap.Conn, error) {
	addr := fmt.Sprintf("ldap://%s:%d", cfg.FQDN, cfg.Port)
	var conn *ldap.Conn
	var err error

	if cfg.UseTLS {
		addr = fmt.Sprintf("ldaps://%s:%d", cfg.FQDN, cfg.Port)
		tlsConfig := getSecureTLSConfig()
		conn, err = ldap.DialURL(addr, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP at %s: %w", addr, err)
	}

	if err := conn.Bind(cfg.BindDN, cfg.Password); err != nil {
		// Check the error return from conn.Close() when binding fails.
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("failed to close LDAP connection after bind failure: %v\n", cerr)
		}
		return nil, fmt.Errorf("failed to bind to LDAP as %s: %w", cfg.BindDN, err)
	}

	return conn, nil
}
