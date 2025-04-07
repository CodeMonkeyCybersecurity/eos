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

	// Step 5: Interactive prompt as a last resort
	if cfg, err := LoadFromPrompt(); err == nil {
		fmt.Println("✅ LDAP config loaded from prompt:", cfg.FQDN)
		return cfg, "prompt", nil
	}

	// Step 6: Fallback defaults
	cfg := DefaultLDAPConfig()
	fmt.Println("⚠️  Using fallback LDAP config:", cfg.FQDN)
	return cfg, "default", nil
}

func LoadFromVault() (*LDAPConfig, error) {
	var cfg LDAPConfig
	err := vault.ReadFallbackSecrets("ldap", &cfg)
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

// LoadFromPrompt interactively prompts for LDAP values and remembers them via Vault
func LoadFromPrompt() (*LDAPConfig, error) {
	fqdn, err := vault.RememberFQDN()
	if err != nil {
		return nil, err
	}
	bindDN, err := vault.RememberBindDN()
	if err != nil {
		return nil, err
	}
	password, err := vault.RememberPassword()
	if err != nil {
		return nil, err
	}
	userBase, err := vault.RememberUserBase()
	if err != nil {
		return nil, err
	}
	roleBase, err := vault.RememberGroupBase()
	if err != nil {
		return nil, err
	}
	adminRole, err := vault.RememberAdminRole()
	if err != nil {
		return nil, err
	}
	readonlyRole, err := vault.RememberReadonlyRole()
	if err != nil {
		return nil, err
	}

	return &LDAPConfig{
		FQDN:         fqdn,
		Port:         389, // TODO: add RememberPort() later if needed
		UseTLS:       false,
		BindDN:       bindDN,
		Password:     password,
		UserBase:     userBase,
		RoleBase:     roleBase,
		AdminRole:    adminRole,
		ReadonlyRole: readonlyRole,
	}, nil
}
