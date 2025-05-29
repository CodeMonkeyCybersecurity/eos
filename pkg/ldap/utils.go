// pkg/ldap/utils.go

package ldap

import (
	"context"
	"os/exec"
	"strings"
	"time"
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

func TryDetectFromContainer() *LDAPConfig {
	rc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(rc, "docker", "ps", "--format", "{{.Names}}").Output()
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
