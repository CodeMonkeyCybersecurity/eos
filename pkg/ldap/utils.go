// pkg/ldap/utils.go

package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ExtractCN returns the CN portion from a DN string
func ExtractCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if strings.HasPrefix(part, "cn=") {
			return strings.TrimPrefix(part, "cn=")
		}
	}
	return ""
}

// ExtractUID returns the UID portion from a DN string
func ExtractUID(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if strings.HasPrefix(part, "uid=") {
			return strings.TrimPrefix(part, "uid=")
		}
	}
	return ""
}

// NormalizeDN ensures a DN is lowercased and trimmed
func NormalizeDN(dn string) string {
	return strings.ToLower(strings.TrimSpace(dn))
}

func ConnectWithConfig(cfg *LDAPConfig) (*ldap.Conn, error) {
	scheme := "ldap"
	if cfg.UseTLS {
		scheme = "ldaps"
	}

	url := fmt.Sprintf("%s://%s:%d", scheme, cfg.FQDN, cfg.Port)

	conn, err := ldap.DialURL(url)
	if err != nil {
		return nil, fmt.Errorf("failed to dial LDAP URL: %w", err)
	}

	// Upgrade to StartTLS if needed (not ldaps)
	if cfg.UseTLS && scheme == "ldap" {
		err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	if err := conn.Bind(cfg.BindDN, cfg.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	return conn, nil
}

func TryDetectFromContainer() *LDAPConfig {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.Names}}").Output()
	if err != nil {
		return nil
	}

	containers := strings.Split(string(out), "\n")
	for _, name := range containers {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if strings.Contains(name, "ldap") || strings.Contains(name, "389ds") {
			// Assumes host access via localhost:389
			return &LDAPConfig{
				FQDN:         "localhost",
				Port:         389,
				UseTLS:       false,
				BindDN:       "cn=admin,dc=domain,dc=com",
				Password:     "", // Can fallback later
				UserBase:     "ou=Users,dc=domain,dc=com",
				RoleBase:     "ou=Groups,dc=domain,dc=com",
				AdminRole:    "AdminRole",
				ReadonlyRole: "ReadonlyRole",
			}
		}
	}

	return nil
}

func ReturnFallbackDefaults() *LDAPConfig {
	return &LDAPConfig{
		FQDN:         "localhost",
		Port:         389,
		UseTLS:       false,
		BindDN:       "cn=admin,dc=domain,dc=com",
		Password:     "",
		UserBase:     "ou=Users,dc=domain,dc=com",
		RoleBase:     "ou=Groups,dc=domain,dc=com",
		AdminRole:    "AdminRole",
		ReadonlyRole: "ReadonlyRole",
	}
}
