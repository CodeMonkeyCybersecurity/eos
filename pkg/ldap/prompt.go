/* pkg/ldap/prompt.go */

package ldap

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// PromptLDAPDetails interactively builds an LDAPConfig using field metadata.
func promptLDAPDetails() (*LDAPConfig, error) {
	cfg := &LDAPConfig{}
	if _, err := vault.GetVaultClient(); err == nil {
		_ = vault.LoadFromVaultAt(context.Background(), "secret", consts.LDAPVaultPath, cfg) // best-effort prefill
	}

	for fieldName, meta := range LDAPFieldMeta {
		val := getLDAPField(cfg, fieldName)

		if val == "" || meta.Required {
			if meta.Sensitive {
				secret, err := interaction.PromptPassword(meta.Label)
				if err != nil {
					return nil, err
				}
				val = secret
			} else {
				val = interaction.PromptInput(meta.Label, meta.Help)
			}
			setLDAPField(cfg, fieldName, val)
		}
	}

	if err := vault.SaveToVault(consts.LDAPVaultPath, cfg); err != nil {
		fmt.Printf("⚠️  Warning: failed to save LDAP config to Vault: %v\n", err)
	}

	return cfg, nil
}

func getLDAPField(cfg *LDAPConfig, field string) string {
	switch field {
	case "FQDN":
		return cfg.FQDN
	case "BindDN":
		return cfg.BindDN
	case "Password":
		return cfg.Password
	case "UserBase":
		return cfg.UserBase
	case "RoleBase":
		return cfg.RoleBase
	case "AdminRole":
		return cfg.AdminRole
	case "ReadonlyRole":
		return cfg.ReadonlyRole
	default:
		return ""
	}
}

func setLDAPField(cfg *LDAPConfig, field, value string) {
	switch field {
	case "FQDN":
		cfg.FQDN = value
	case "BindDN":
		cfg.BindDN = value
	case "Password":
		cfg.Password = value
	case "UserBase":
		cfg.UserBase = value
	case "RoleBase":
		cfg.RoleBase = value
	case "AdminRole":
		cfg.AdminRole = value
	case "ReadonlyRole":
		cfg.ReadonlyRole = value
	}
}
