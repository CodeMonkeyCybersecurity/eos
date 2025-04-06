package ldap

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
)

func PromptLDAPDetails() (*LDAPConfig, error) {
	cfg := &LDAPConfig{}
	_ = storage.LoadFromVault(consts.LDAPVaultPath, cfg) // best-effort

	if cfg.FQDN == "" {
		cfg.FQDN = interaction.PromptInput("FQDN", "FQDN of your LDAP server")
	}
	if cfg.BindDN == "" {
		cfg.BindDN = interaction.PromptInput("BindDN", "Bind DN")
	}
	if cfg.Password == "" {
		var err error
		cfg.Password, err = interaction.PromptPassword("Bind password")
		if err != nil {
			return nil, err
		}
	}

	cfg.UserBase = interaction.PromptInput("UserBase", "User base DN")
	cfg.RoleBase = interaction.PromptInput("RoleBase", "Role base DN")
	cfg.AdminRole = interaction.PromptInput("AdminRole", "Admin group name")
	cfg.ReadonlyRole = interaction.PromptInput("ReadonlyRole", "Readonly group name")

	if cfg.FQDN == "" || cfg.BindDN == "" || cfg.Password == "" || cfg.UserBase == "" || cfg.RoleBase == "" {
		return nil, fmt.Errorf("missing required LDAP fields")
	}

	if err := storage.SaveToVault(consts.LDAPVaultPath, cfg); err != nil {
		fmt.Printf("⚠️  Warning: failed to save LDAP config to Vault: %v\n", err)
	}

	return cfg, nil
}
