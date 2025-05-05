package secure

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var SecureVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Applies hardening and provisioning to a running Vault instance",
	RunE: eoscli.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("secure-vault")

		swapOff, _ := cmd.Flags().GetBool("disable-swap")
		coreDumpOff, _ := cmd.Flags().GetBool("disable-coredump")

		zap.L().Info("🔐 Connecting to Vault")
		client, err := vault.EnsureVaultReady()
		if err != nil {
			return logger.LogErrAndWrap("secure vault: connect failed", err)
		}

		if vault.IsVaultSealed(client) {
			return fmt.Errorf("vault is sealed — please run `eos enable vault` before `secure vault`")
		}

		// TLS check
		if !strings.HasPrefix(client.Address(), "https://") {
			zap.L().Warn("⚠ Vault is not running over TLS; end-to-end encryption is strongly recommended")
		}

		// 1️⃣ Ensure EOS Policy
		if err := vault.EnsurePolicy(); err != nil {
			return logger.LogErrAndWrap("secure vault: ensure policy", err)
		}

		// 2️⃣ Ensure AppRole + aliases
		if err := vault.EnableVault(client, log); err != nil {
			return logger.LogErrAndWrap("secure vault: enable auth methods", err)
		}

		// 3️⃣ Re-provision AppRole
		roleID, secretID, err := vault.EnsureAppRole(client, shared.DefaultAppRoleOptions())
		if err != nil {
			return logger.LogErrAndWrap("secure vault: create approle", err)
		}
		if err := vault.WriteAppRoleFiles(roleID, secretID); err != nil {
			return logger.LogErrAndWrap("secure vault: write approle creds", err)
		}
		zap.L().Info("✅ AppRole credentials written", zap.String("role_id", roleID))

		// 4️⃣ Load init result + confirm secure storage
		initRes, err := vault.LoadOrPromptInitResult()
		if err != nil {
			return fmt.Errorf("failed to load init result: %w", err)
		}
		if err := vault.ConfirmSecureStorage(initRes); err != nil {
			return fmt.Errorf("secure storage confirmation failed: %w", err)
		}

		// 5️⃣ Securely erase vault_init.json
		if err := crypto.SecureErase(shared.VaultInitPath); err != nil {
			return fmt.Errorf("failed to erase vault init file: %w", err)
		}
		zap.L().Info("✅ Securely erased vault init file")

		// 6️⃣ Disable swap (optional)
		if swapOff {
			if err := execute.Execute("swapoff", "-a"); err != nil {
				zap.L().Warn("⚠ Failed to disable swap; you may need root privileges", zap.Error(err))
			} else {
				zap.L().Info("✅ Swap disabled")
			}
		}

		// 7️⃣ Disable core dumps (optional)
		if coreDumpOff {
			if err := execute.Execute("ulimit", "-c", "0"); err != nil {
				zap.L().Warn("⚠ Failed to disable core dumps; update systemd unit with LimitCORE=0", zap.Error(err))
			} else {
				zap.L().Info("✅ Core dumps disabled")
			}
		}

		// 📋 Final reminders
		zap.L().Info("ℹ️ Reminder: Check audit device configuration and firewall rules")
		zap.L().Info("ℹ️ Reminder: Validate filesystem permissions on Vault binary and configs")

		// 📋 Final summary
		zap.L().Info("🔒 Vault hardening completed",
			zap.Bool("vault_hardened", true),
		)
		return nil
	}),
}

func init() {
	SecureVaultCmd.Flags().Bool("disable-swap", false, "Disable swap on the system")
	SecureVaultCmd.Flags().Bool("disable-coredump", false, "Disable core dumps on the system")
	SecureCmd.AddCommand(SecureVaultCmd)
}
