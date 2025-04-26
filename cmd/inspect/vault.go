// cmd/inspect/vault.go
package inspect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// InspectVaultInitCmd displays Vault initialization keys and root token
var InspectVaultInitCmd = &cobra.Command{
	Use:   "vault-init",
	Short: "Inspect Vault initialization keys and root token",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-vault-init")

		initResult, err := vault.LoadVaultInitResult(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "inspect vault-init: load init result", err)
		}

		log.Info("Vault Initialization Result Retrieved")
		log.Info("Root Token", zap.String("root_token", crypto.Redact(initResult.RootToken)))

		for i, key := range initResult.KeysB64 {
			log.Info("Unseal Key", zap.Int("key_number", i+1), zap.String("key_value", crypto.Redact(key)))
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
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-vault")

		log.Info("Listing secrets under secret/eos")
		entries, err := vault.ListUnder(shared.EosIdentity, log)
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
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-vault-agent")

		if err := checkVaultAgentService(log); err != nil {
			return err
		}
		if err := checkVaultTokenFile(log); err != nil {
			return err
		}
		if err := runVaultTestQuery(log); err != nil {
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
		log := zap.L().Named("inspect-vault-ldap")
		cfg := &ldap.LDAPConfig{}

		err := vault.ReadFromVaultAt(context.Background(), shared.LDAPVaultMount, shared.LDAPVaultPath, cfg, log)
		if err != nil {
			log.Error("Failed to load LDAP config from Vault", zap.Error(err))
			return fmt.Errorf("could not load LDAP config from Vault: %w", err)
		}

		log.Info("LDAP Config Retrieved",
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

func checkVaultAgentService(log *zap.Logger) error {
	log.Info("Checking Vault Agent systemd service", zap.String("service", shared.VaultAgentService))

	cmd := exec.Command("systemctl", "is-active", "--quiet", shared.VaultAgentService)
	if err := cmd.Run(); err != nil {
		log.Error("Vault Agent service inactive", zap.Error(err))
		return fmt.Errorf("vault agent service is not running")
	}

	log.Info("Vault Agent service is active")
	return nil
}

func checkVaultTokenFile(log *zap.Logger) error {
	log.Info("Checking Vault Agent token file", zap.String("path", shared.VaultAgentTokenPath))

	if _, err := os.Stat(shared.VaultAgentTokenPath); os.IsNotExist(err) {
		log.Error("Vault token file missing", zap.String("path", shared.VaultAgentTokenPath))
		return fmt.Errorf("vault token file not found at %s", shared.VaultAgentTokenPath)
	}

	log.Info("Vault token file exists", zap.String("path", shared.VaultAgentTokenPath))
	return nil
}

func runVaultTestQuery(log *zap.Logger) error {
	log.Info("Running test query using Vault Agent token", zap.String("path", shared.TestKVPath))

	cmd := exec.Command("sudo", "-u", shared.EosIdentity, "vault", "kv", "get", "-format=json", shared.TestKVPath)
	cmd.Env = append(os.Environ(), "VAULT_TOKEN_PATH="+shared.VaultAgentTokenPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Vault test query failed", zap.ByteString("output", output), zap.Error(err))
		return fmt.Errorf("vault test query failed: %w", err)
	}

	log.Info("Vault test query succeeded", zap.ByteString("response", output))
	return nil
}

func init() {
	InspectVaultCmd.AddCommand(InspectVaultAgentCmd)
	InspectVaultCmd.AddCommand(InspectVaultLDAPCmd)
	InspectCmd.AddCommand(InspectVaultCmd)
	InspectCmd.AddCommand(InspectVaultInitCmd)
}
