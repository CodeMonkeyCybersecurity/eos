/* pkg/ldap/prompt.go */

package ldap

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/types"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// PromptLDAPDetails interactively builds an LDAPConfig using field metadata.
func PromptLDAPDetails() (*LDAPConfig, error) {
	cfg := &LDAPConfig{}
	if _, err := vault.GetVaultClient(); err == nil {
		_ = vault.ReadFromVaultAt(context.Background(), "secret", types.LDAPVaultPath, cfg) // best-effort prefill
	}

	for fieldName, meta := range LDAPFieldMeta {
		val := GetLDAPField(cfg, fieldName)

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
			SetLDAPField(cfg, fieldName, val)
		}
	}

	if err := vault.WriteToVault(types.LDAPVaultPath, cfg); err != nil {
		fmt.Printf("⚠️  Warning: failed to save LDAP config to Vault: %v\n", err)
	}

	return cfg, nil
}

func GetLDAPField(cfg *LDAPConfig, field string) string {
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

func SetLDAPField(cfg *LDAPConfig, field, value string) {
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
