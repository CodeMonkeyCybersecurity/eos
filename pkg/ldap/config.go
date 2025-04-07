// pkg/ldap/config.go
package ldap

import (
	"errors"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

func LoadLDAPConfig() (*LDAPConfig, string, error) {
	loaders := []struct {
		name string
		load func() (*LDAPConfig, error)
	}{
		{"vault", loadFromVault},
		{"env", loadFromEnv},
		{"host", tryDetectFromHost},
		{"container", tryDetectFromContainer},
		{"prompt", loadFromPrompt},
	}

	for _, source := range loaders {
		if cfg, err := source.load(); err == nil && cfg.FQDN != "" {
			fmt.Printf("✅ LDAP config loaded from %s: %s\n", source.name, cfg.FQDN)
			return cfg, source.name, nil
		}
	}

	// Fallback default
	cfg := DefaultLDAPConfig()
	fmt.Printf("⚠️  Using fallback LDAP config: %s\n", cfg.FQDN)
	return cfg, "default", nil
}

func loadFromVault() (*LDAPConfig, error) {
	var cfg LDAPConfig
	if err := vault.Load("ldap", &cfg); err != nil || cfg.FQDN == "" {
		return nil, errors.New("LDAP config not found in Vault")
	}
	return &cfg, nil
}

func loadFromEnv() (*LDAPConfig, error) {
	fqdn := os.Getenv("LDAP_FQDN")
	if fqdn == "" {
		return nil, errors.New("LDAP_FQDN not set")
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
	}, nil
}

func tryDetectFromHost() (*LDAPConfig, error) {
	cfg := TryDetectFromHost()
	if cfg == nil {
		return nil, errors.New("host detection failed")
	}
	return cfg, nil
}

func tryDetectFromContainer() (*LDAPConfig, error) {
	cfg := TryDetectFromContainer()
	if cfg == nil {
		return nil, errors.New("container detection failed")
	}
	return cfg, nil
}

func loadFromPrompt() (*LDAPConfig, error) {
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
		Port:         389,
		UseTLS:       false,
		BindDN:       bindDN,
		Password:     password,
		UserBase:     userBase,
		RoleBase:     roleBase,
		AdminRole:    adminRole,
		ReadonlyRole: readonlyRole,
	}, nil
}
