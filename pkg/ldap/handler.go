/* pkg/ldap/handler.go */

package ldap

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/go-ldap/ldap/v3"
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
	cfg, source, err := ReadConfig(rc)
	if err != nil {
		return nil, nil, fmt.Errorf("could not load LDAP config: %w", err)
	}

	fmt.Printf(" Connecting to LDAP via %s config (%s:%d)...\n", source, cfg.FQDN, cfg.Port)

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
			fmt.Printf("failed to close LDAP connection after bind failure: %v\n", cerr)
		}
		return nil, nil, fmt.Errorf("failed to bind to LDAP as %s: %w", cfg.BindDN, err)
	}

	fmt.Println(" Connected and bound to LDAP successfully.")
	return conn, cfg, nil
}

// getSecureTLSConfig returns TLS configuration with proper security settings for LDAP
func getSecureTLSConfig() *tls.Config {
	// Allow insecure TLS only in development/testing environments
	if os.Getenv("EOS_INSECURE_TLS") == "true" || os.Getenv("GO_ENV") == "test" {
		return &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	// Secure TLS configuration for production LDAP connections
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
