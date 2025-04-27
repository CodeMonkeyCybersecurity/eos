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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// TestConnection attempts a bind to verify the LDAP connection works.
func CheckConnection(cfg *LDAPConfig, log *zap.Logger) error {
	conn, err := ConnectWithGivenConfig(cfg, log)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer shared.SafeClose(conn, log)

	return nil
}

// TryReadFromVault attempts to load the LDAP config from Vault.
// It returns nil if not found or incomplete.
func TryReadFromVault(client *api.Client, log *zap.Logger) (*LDAPConfig, error) {
	var cfg LDAPConfig
	if err := vault.Read(client, "secret/ldap/config", &cfg, log); err != nil {
		return nil, err
	}
	if cfg.FQDN == "" || cfg.BindDN == "" {
		return nil, errors.New("incomplete LDAP config in Vault")
	}
	return &cfg, nil
}

func TryLoadFromEnv(log *zap.Logger) *LDAPConfig {
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

	useTLS := os.Getenv("LDAP_USE_TLS") == "true"

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

func TryDetectFromHost(log *zap.Logger) *LDAPConfig {
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
func IsPortOpen(port int, log *zap.Logger) bool {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// IsSystemdUnitActive checks if a systemd service (e.g. slapd) is active
func IsSystemdUnitActive(name string, log *zap.Logger) bool {
	out, err := exec.Command("systemctl", "is-active", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

func runLDAPProbe(log *zap.Logger) error {
	cmd := exec.Command("ldapsearch", "-x", "-H", "ldap://localhost", "-b", "", "-s", "base")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func runLDAPAuthProbe(bindDN, password string, log *zap.Logger) error {
	cmd := exec.Command("ldapsearch", "-x", "-H", "ldap://localhost", "-D", bindDN, "-w", password, "-b", "", "-s", "base")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
