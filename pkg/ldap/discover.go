// pkg/ldap/discovery.go
package ldap

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// TryLoadFromVault attempts to load the LDAP config from Vault.
// It returns nil if not found or incomplete.
func TryLoadFromVault() (*LDAPConfig, error) {
	var cfg LDAPConfig
	if err := vault.LoadWithFallback("secret/ldap/config", &cfg); err != nil {
		return nil, err
	}
	if cfg.FQDN == "" || cfg.BindDN == "" {
		return nil, errors.New("incomplete LDAP config in Vault")
	}
	return &cfg, nil
}

func TryLoadFromEnv() *LDAPConfig {
	fqdn := os.Getenv("LDAP_FQDN")
	bind := os.Getenv("LDAP_BIND_DN")
	pass := os.Getenv("LDAP_PASSWORD")

	if fqdn == "" || bind == "" || pass == "" {
		return nil
	}

	portStr := os.Getenv("LDAP_PORT")
	port := 389
	if portStr != "" {
		if parsed, err := strconv.Atoi(portStr); err == nil {
			port = parsed
		}
	}

	useTLS := false
	if os.Getenv("LDAP_USE_TLS") == "true" {
		useTLS = true
	}

	return &LDAPConfig{
		FQDN:         fqdn,
		Port:         port,
		UseTLS:       useTLS,
		BindDN:       bind,
		Password:     pass,
		UserBase:     os.Getenv("LDAP_USER_BASE"),
		RoleBase:     os.Getenv("LDAP_GROUP_BASE"),
		AdminRole:    os.Getenv("LDAP_ADMIN_ROLE"),
		ReadonlyRole: os.Getenv("LDAP_READONLY_ROLE"),
	}
}

func TryDetectFromHost() *LDAPConfig {
	timeout := 500 * time.Millisecond
	conn, err := net.DialTimeout("tcp", "localhost:389", timeout)
	if err != nil {
		return nil // Port 389 not open on localhost
	}
	_ = conn.Close()

	return &LDAPConfig{
		FQDN:         "localhost",
		Port:         389,
		UseTLS:       false,
		BindDN:       "cn=admin,dc=domain,dc=com",
		Password:     "", // prompt or fallback later
		UserBase:     "ou=Users,dc=domain,dc=com",
		RoleBase:     "ou=Groups,dc=domain,dc=com",
		AdminRole:    "AdminRole",
		ReadonlyRole: "ReadonlyRole",
	}
}

// IsPortOpen checks if a port is listening on localhost (e.g. 389 for LDAP)
func IsPortOpen(port int) bool {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// IsSystemdUnitActive checks if a systemd service (e.g. slapd) is active
func IsSystemdUnitActive(name string) bool {
	out, err := exec.Command("systemctl", "is-active", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}
