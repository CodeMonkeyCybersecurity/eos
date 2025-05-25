// cmd/inspect/vault.go
package read

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	InspectVaultCmd.AddCommand(InspectVaultAgentCmd)
	InspectVaultCmd.AddCommand(InspectVaultLDAPCmd)
	ReadCmd.AddCommand(InspectVaultCmd)
	ReadCmd.AddCommand(InspectVaultInitCmd)
}

// InspectVaultInitCmd displays Vault initialization keys, root token, and eos user credentials.
var InspectVaultInitCmd = &cobra.Command{
	Use:   "vault-init",
	Short: "Inspect Vault initialization keys, root token, and eos credentials",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-vault-init")

		// Load Vault Init Result
		initResult, err := vault.ReadVaultInitResult()
		if err != nil {
			return logger.LogErrAndWrap("inspect vault-init: load init result", err)
		}

		// Load eos password credentials
		eosCreds, err := eos_unix.LoadPasswordFromSecrets()
		if err != nil {
			log.Warn("⚠️ Could not load eos password file", zap.Error(err))
		}

		// ---------------------------------------
		// Print Vault Initialization Data
		// ---------------------------------------
		fmt.Println("\n🔑 Vault Initialization Result")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("Root Token:  %s\n", initResult.RootToken)
		for i, key := range initResult.KeysB64 {
			fmt.Printf("Unseal Key %d: %s\n", i+1, key)
		}

		// ---------------------------------------
		// Print EOS Credentials
		// ---------------------------------------
		if eosCreds != nil {
			log.Info("👤 EOS User Credentials printed")
			fmt.Println("\n👤 EOS User Credentials")
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Printf("Username: %s\n", eosCreds.Username)
			fmt.Printf("Password: %s\n", eosCreds.Password)
		} else {
			log.Info("⚠️  EOS credentials not found (expected in secrets dir)")
			fmt.Println("\n ⚠️  EOS credentials not found (expected in secrets dir)")
			fmt.Println("👉  You can refresh EOS credentials safely by running:")
			fmt.Println("    eos refresh eos-passwd")
			fmt.Println("   (This will regenerate a strong password and save it securely.)")
		}

		// ---------------------------------------
		// Reminders
		// ---------------------------------------
		fmt.Println("\n⚡ Please back up these credentials securely.")
		fmt.Println("👉 Next: run 'eos enable vault' to unseal Vault.")

		// Structured logs
		log.Info("Vault Initialization Result Retrieved")
		log.Info("Root Token", zap.String("root_token", crypto.Redact(initResult.RootToken)))
		for i := range initResult.KeysB64 {
			log.Info("Unseal Key loaded", zap.Int("key_number", i+1))
		}
		if eosCreds != nil {
			log.Info("EOS credentials loaded", zap.String("username", eosCreds.Username))
		}

		log.Warn("⚡ Please back up your Vault credentials securely")
		log.Info("👉 Next step: run 'eos enable vault' to unseal")

		return nil
	}),
}

// InspectVaultCmd lists secrets stored in Vault
var InspectVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Inspect current Vault paths (requires root or eos)",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-vault")

		log.Info("Listing secrets under secret/eos")
		entries, err := vault.ListUnder(shared.EosID)
		if err != nil {
			log.Error("Failed to list Vault secrets", zap.Error(err))
			return fmt.Errorf("could not list Vault contents: %w", err)
		}

		for _, entry := range entries {
			log.Info("Found Vault entry", zap.String("entry", "secret/eos/"+strings.TrimSuffix(entry, "/")))
		}

		log.Info("Vault entries inspection complete", zap.Int("count", len(entries)))
		return nil
	}),
}

// InspectVaultAgentCmd checks Vault Agent service and token
var InspectVaultAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Check Vault Agent status and basic functionality",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-vault-agent")

		if err := vault.CheckVaultAgentService(); err != nil {
			return err
		}
		if err := vault.CheckVaultTokenFile(); err != nil {
			return err
		}
		if err := vault.RunVaultTestQuery(); err != nil {
			return err
		}

		log.Info("Vault Agent inspection complete and healthy")
		return nil
	}),
}

// InspectVaultLDAPCmd views LDAP config stored in Vault
var InspectVaultLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "View stored LDAP config in Vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		zap.L().Named("inspect-vault-ldap")
		cfg := &ldap.LDAPConfig{}

		err := vault.ReadFromVaultAt(context.Background(), shared.LDAPVaultMount, shared.LDAPVaultPath, cfg)
		if err != nil {
			zap.L().Error("Failed to load LDAP config from Vault", zap.Error(err))
			return fmt.Errorf("could not load LDAP config from Vault: %w", err)
		}

		zap.L().Info("LDAP Config Retrieved",
			zap.String("fqdn", cfg.FQDN),
			zap.String("bind_dn", cfg.BindDN),
			zap.String("user_base", cfg.UserBase),
			zap.String("role_base", cfg.RoleBase),
			zap.String("admin_role", cfg.AdminRole),
			zap.String("readonly_role", cfg.ReadonlyRole),
			zap.String("password", crypto.Redact(cfg.Password)),
		)
		return nil
	},
}

var InspectSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "List and view EOS secrets (redacted)",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-secrets")

		files, err := os.ReadDir(shared.SecretsDir)
		if err != nil {
			return logger.LogErrAndWrap("inspect secrets: read secrets dir", err)
		}

		if len(files) == 0 {
			fmt.Println("❌ No secrets found in", shared.SecretsDir)
			return nil
		}

		fmt.Println("\n🔐 EOS Secrets Directory")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		for _, file := range files {
			path := filepath.Join(shared.SecretsDir, file.Name())

			data, err := os.ReadFile(path)
			if err != nil {
				log.Warn("❌ Failed to read secret file", zap.String("path", path), zap.Error(err))
				continue
			}

			var content map[string]interface{}
			if err := json.Unmarshal(data, &content); err != nil {
				log.Warn("❌ Failed to parse JSON secret", zap.String("path", path), zap.Error(err))
				fmt.Printf("- %s (Unreadable JSON)\n", file.Name())
				continue
			}

			fmt.Printf("\n📄 File: %s\n", file.Name())
			for k, v := range content {
				valStr := fmt.Sprintf("%v", v)
				if strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "key") {
					valStr = crypto.Redact(valStr)
				}
				fmt.Printf("    %s: %s\n", k, valStr)
			}
		}

		fmt.Println("\n✅ Secrets inspection complete.")
		return nil
	}),
}
