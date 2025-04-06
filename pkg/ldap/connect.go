package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// Connect returns a default LDAP connection using autodiscovered config
func Connect() (*ldap.Conn, error) {
	conn, _, err := ConnectWithConfig()
	if err != nil {
		return nil, fmt.Errorf("Connect() failed: %w", err)
	}
	return conn, nil
}

// ConnectWithConfig tries all discovery methods to return an active LDAP connection
func ConnectWithConfig() (*ldap.Conn, *LDAPConfig, error) {
	cfg, source, err := LoadLDAPConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("could not load LDAP config: %w", err)
	}

	fmt.Printf("🔌 Connecting to LDAP via %s config (%s:%d)...\n", source, cfg.FQDN, cfg.Port)

	addr := fmt.Sprintf("ldap://%s:%d", cfg.FQDN, cfg.Port)
	var conn *ldap.Conn

	if cfg.UseTLS {
		addr = fmt.Sprintf("ldaps://%s:%d", cfg.FQDN, cfg.Port)
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		conn, err = ldap.DialURL(addr, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(addr)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to LDAP at %s: %w", addr, err)
	}

	err = conn.Bind(cfg.BindDN, cfg.Password)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to bind to LDAP as %s: %w", cfg.BindDN, err)
	}

	fmt.Println("✅ Connected and bound to LDAP successfully.")
	return conn, cfg, nil
}

func ConnectWithGivenConfig(cfg *LDAPConfig) (*ldap.Conn, error) {
	addr := fmt.Sprintf("ldap://%s:%d", cfg.FQDN, cfg.Port)
	var conn *ldap.Conn
	var err error

	if cfg.UseTLS {
		addr = fmt.Sprintf("ldaps://%s:%d", cfg.FQDN, cfg.Port)
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		conn, err = ldap.DialURL(addr, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		conn, err = ldap.DialURL(addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP at %s: %w", addr, err)
	}

	if err := conn.Bind(cfg.BindDN, cfg.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind to LDAP as %s: %w", cfg.BindDN, err)
	}

	return conn, nil
}
