// pkg/ldap/config.go
package ldap

import (
	"errors"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

func LoadLDAPConfig() (*LDAPConfig, string, error) {
	if cfg, err := LoadFromVault(); err == nil && cfg.FQDN != "" {
		return cfg, "vault", nil
	}
	if cfg := LoadFromEnv(); cfg != nil && cfg.FQDN != "" {
		return cfg, "env", nil
	}
	if cfg := TryDetectFromHost(); cfg != nil {
		return cfg, "host", nil
	}
	if cfg := TryDetectFromContainer(); cfg != nil {
		return cfg, "container", nil
	}
	return ReturnFallbackDefaults(), "fallback", nil
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
