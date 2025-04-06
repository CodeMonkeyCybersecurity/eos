// pkg/ldap/config.go
package ldap

import (
	"errors"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

func LoadLDAPConfig() (*LDAPConfig, string, error) {
	// Step 1: Attempt to load from Vault
	if cfg, err := LoadFromVault(); err == nil && cfg.FQDN != "" {
		fmt.Println("✅ LDAP config loaded from Vault:", cfg.FQDN)
		return cfg, "vault", nil
	}

	// Step 2: Fallback to environment variables
	if cfg := LoadFromEnv(); cfg != nil && cfg.FQDN != "" {
		fmt.Println("✅ LDAP config loaded from env:", cfg.FQDN)
		return cfg, "env", nil
	}

	// Step 3: Detect from host (systemd or open port)
	if cfg := TryDetectFromHost(); cfg != nil {
		fmt.Println("✅ LDAP config auto-detected from host:", cfg.FQDN)
		return cfg, "host", nil
	}

	// Step 4: Detect from Docker container
	if cfg := TryDetectFromContainer(); cfg != nil {
		fmt.Println("✅ LDAP config auto-detected from container:", cfg.FQDN)
		return cfg, "container", nil
	}

	// Step 5: Fallback defaults
	cfg := ReturnFallbackDefaults()
	fmt.Println("⚠️  Using fallback LDAP config:", cfg.FQDN)
	return cfg, "default", nil
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
