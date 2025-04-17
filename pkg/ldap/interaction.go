/* pkg/ldap/helper.go */

package ldap

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/types"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"go.uber.org/zap"
)

func InteractiveLDAPQuery(log *zap.Logger) error {
	cfg := &LDAPConfig{}

	// Try to load existing config from Vault to prefill
	if err := vault.ReadFromVaultAt(context.Background(), "secret", types.LDAPVaultPath, cfg, log); err == nil {
		fmt.Println("✅ LDAP config prefilled from Vault")
	} else {
		fmt.Printf("⚠️  Vault fallback: could not load LDAP config: %v\n", err)
	}

	// Prompts
	proto := interaction.PromptInput("Connection type [ldap, ldaps, ldapi]", "ldap", log)
	host := interaction.PromptInput("LDAP host or IP", cfg.FQDN, log)
	bindDN := interaction.PromptInput("Bind DN (e.g. cn=admin,dc=domain,dc=com)", cfg.BindDN, log)
	if bindDN == "" {
		fmt.Println("⚠️  No BindDN provided — defaulting to cn=anonymous instead.")
		bindDN = "cn=anonymous"
	}

	password, err := interaction.PromptPasswordWithDefault("LDAP password [press Enter to keep existing]", cfg.Password, log)
	if err != nil {
		fmt.Println("⚠️  No Password provided.")
		return err
	}
	fmt.Println("Search base DN (e.g. ou=Users,dc=domain,dc=com). Leave blank to search entire tree.")
	baseDN := interaction.PromptInput("Search base DN", cfg.UserBase, log)
	if baseDN == "" || baseDN == `""` {
		inferred := inferBaseDN(bindDN, log)
		if inferred != "" {
			fmt.Printf("⚠️  No base DN provided — using inferred root (%s)\n", inferred)
			baseDN = inferred
		} else {
			fmt.Println("⚠️  No base DN could be inferred — aborting for safety.")
			return fmt.Errorf("invalid base DN")
		}
	}

	filter := interaction.PromptInput("Search filter", "(objectClass=*)", log)
	attrLine := interaction.PromptInput("Attributes (comma-separated, or leave blank for all)", "", log)
	attrs := strings.FieldsFunc(attrLine, func(r rune) bool { return r == ',' || r == ' ' })

	// Save values into cfg
	cfg.FQDN = host
	cfg.BindDN = bindDN
	cfg.Password = password
	cfg.UserBase = baseDN

	// Save config to Vault
	if err := vault.WriteToVault(types.LDAPVaultPath, cfg); err != nil {
		fmt.Printf("⚠️  Warning: failed to save LDAP config to Vault: %v\n", err)
	}

	// Build URI and args
	uri := proto + "://" + host
	maxResultsStr := strconv.Itoa(MaxResults) // from ldap/flags.go
	args := []string{"-x", "-H", uri, "-D", bindDN, "-w", password, "-b", baseDN, "-z", maxResultsStr, filter}
	args = append(args, attrs...)

	fmt.Println("\n➡️  Running:", "ldapsearch", strings.Join(args, " "))
	cmd := exec.Command("ldapsearch", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func inferBaseDN(bindDN string, log *zap.Logger) string {
	log.Debug("Inferring base DN from BindDN", zap.String("bindDN", bindDN))

	parts := strings.Split(bindDN, ",")
	var base []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			base = append(base, part)
		}
	}

	inferred := strings.Join(base, ",")
	if inferred == "" {
		log.Warn("Could not infer base DN from BindDN", zap.String("bindDN", bindDN))
	} else {
		log.Info("✅ Inferred base DN", zap.String("baseDN", inferred))
	}

	return inferred
}

func loadFromPrompt(log *zap.Logger) (*LDAPConfig, error) {
	fqdn, err := RememberFQDN(log)
	if err != nil {
		return nil, err
	}
	bindDN, err := RememberBindDN(log)
	if err != nil {
		return nil, err
	}
	password, err := RememberPassword(log)
	if err != nil {
		return nil, err
	}
	userBase, err := RememberUserBase(log)
	if err != nil {
		return nil, err
	}
	roleBase, err := RememberGroupBase(log)
	if err != nil {
		return nil, err
	}
	adminRole, err := RememberAdminRole(log)
	if err != nil {
		return nil, err
	}
	readonlyRole, err := RememberReadonlyRole(log)
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

// PromptLDAPDetails interactively builds an LDAPConfig using field metadata.
func PromptLDAPDetails(log *zap.Logger) (*LDAPConfig, error) {
	cfg := &LDAPConfig{}
	if _, err := vault.GetVaultClient(); err == nil {
		_ = vault.ReadFromVaultAt(context.Background(), "secret", types.LDAPVaultPath, cfg, log)
	}

	for fieldName, meta := range LDAPFieldMeta {
		val := GetLDAPField(cfg, fieldName, log)

		if val == "" || meta.Required {
			if meta.Sensitive {
				secret, err := interaction.PromptPassword(meta.Label, log)
				if err != nil {
					return nil, err
				}
				val = secret
			} else {
				val = interaction.PromptInput(meta.Label, meta.Help, log)
			}
			SetLDAPField(cfg, fieldName, val, log)
		}
	}

	if err := vault.WriteToVault(types.LDAPVaultPath, cfg); err != nil {
		fmt.Printf("⚠️  Warning: failed to save LDAP config to Vault: %v\n", err)
	}

	return cfg, nil
}

func GetLDAPField(cfg *LDAPConfig, field string, log *zap.Logger) string {
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

func SetLDAPField(cfg *LDAPConfig, field, value string, log *zap.Logger) {
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
