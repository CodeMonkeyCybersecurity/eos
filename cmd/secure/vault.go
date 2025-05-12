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

		log.Info("🔐 Connecting to Vault")
		client, err := vault.EnsureVaultReady()
		if err != nil {
			return logger.LogErrAndWrap("secure vault: connect failed", err)
		}

		if vault.IsVaultSealed(client) {
			return fmt.Errorf("vault is sealed — please run `eos enable vault` before `secure vault`")
		}

		// TLS check
		if !strings.HasPrefix(client.Address(), "https://") {
			log.Warn("⚠ Vault is not running over TLS; end-to-end encryption is strongly recommended")
		}

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
		log.Info("✅ Securely erased vault init file")

		// 6️⃣ Disable swap (optional)
		if swapOff {
			if err := execute.Execute("swapoff", "-a"); err != nil {
				log.Warn("⚠ Failed to disable swap; you may need root privileges", zap.Error(err))
			} else {
				log.Info("✅ Swap disabled")
			}
		}

		// 7️⃣ Disable core dumps (optional)
		if coreDumpOff {
			if err := execute.Execute("ulimit", "-c", "0"); err != nil {
				log.Warn("⚠ Failed to disable core dumps; update systemd unit with LimitCORE=0", zap.Error(err))
			} else {
				log.Info("✅ Core dumps disabled")
			}
		}

		// 📋 Final reminders
		log.Info("ℹ️ Reminder: Check audit device configuration and firewall rules")
		log.Info("ℹ️ Reminder: Validate filesystem permissions on Vault binary and configs")

		// 📋 Final summary
		log.Info("🔒 Vault hardening completed",
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
