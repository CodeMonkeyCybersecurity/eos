// pkg/ldap/config.go
package ldap

import (
	"errors"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

func LoadLDAPConfig() (*LDAPConfig, error) {
	// Step 1: Attempt to load from Vault (preferred)
	if cfg, err := LoadFromVault(); err == nil {
		return cfg, nil
	}

	// Step 2: Fallback to environment variables (for runtime override)
	if cfg := LoadFromEnv(); cfg != nil {
		return cfg, nil
	}

	// Step 3: Sane defaults for local dev or demos
	return &LDAPConfig{
		FQDN:         "ldap.domain.com",
		Port:         389,
		UseTLS:       false,
		BindDN:       "cn=admin,dc=domain,dc=com",
		Password:     "",
		UserBase:     "ou=Users,dc=domain,dc=com",
		RoleBase:     "ou=Groups,dc=domain,dc=com",
		AdminRole:    "AdminRole",
		ReadonlyRole: "ReadonlyRole",
	}, nil
}

func LoadFromVault() (*LDAPConfig, error) {
	var cfg LDAPConfig
	err := vault.LoadWithFallback("ldap", &cfg)
	if err != nil || cfg.FQDN == "" {
		return nil, errors.New("LDAP config not found in Vault")
	}
	return &cfg, nil
}

func LoadFromEnv() *LDAPConfig {
	fqdn := os.Getenv("LDAP_FQDN")
	if fqdn == "" {
		return nil
	}

	return &LDAPConfig{
		FQDN:         fqdn,
		Port:         389, // optionally support LDAP_PORT env
		UseTLS:       false,
		BindDN:       os.Getenv("LDAP_BIND_DN"),
		Password:     os.Getenv("LDAP_PASSWORD"),
		UserBase:     os.Getenv("LDAP_USER_BASE"),
		RoleBase:     os.Getenv("LDAP_GROUP_BASE"),
		AdminRole:    os.Getenv("LDAP_ADMIN_ROLE"),
		ReadonlyRole: os.Getenv("LDAP_READONLY_ROLE"),
	}
}
