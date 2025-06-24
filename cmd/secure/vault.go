package secure

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var SecureVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Applies hardening and provisioning to a running Vault instance",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		swapOff, _ := cmd.Flags().GetBool("disable-swap")
		coreDumpOff, _ := cmd.Flags().GetBool("disable-coredump")

		log.Info(" Connecting to Vault")
		client, err := vault.EnsureVaultReady(rc)
		if err != nil {
			return logger.LogErrAndWrap(rc, "secure vault: connect failed", err)
		}

		if vault.IsVaultSealed(client) {
			return fmt.Errorf("vault is sealed — please run `eos enable vault` before `secure vault`")
		}

		// TLS check
		if !strings.HasPrefix(client.Address(), "https://") {
			log.Warn("⚠ Vault is not running over TLS; end-to-end encryption is strongly recommended")
		}

		// Load init result + confirm secure storage
		initRes, err := vault.LoadOrPromptInitResult(rc)
		if err != nil {
			return fmt.Errorf("failed to load init result: %w", err)
		}
		if err := vault.ConfirmSecureStorage(rc, initRes); err != nil {
			return fmt.Errorf("secure storage confirmation failed: %w", err)
		}

		// Securely erase vault_init.json
		if err := crypto.SecureErase(rc.Ctx, shared.VaultInitPath); err != nil {
			return fmt.Errorf("failed to erase vault init file: %w", err)
		}
		log.Info(" Securely erased vault init file")

		// Disable swap (optional)
		if swapOff {
			if err := execute.RunSimple(rc.Ctx, "swapoff", "-a"); err != nil {
				log.Warn("⚠ Failed to disable swap; you may need root privileges", zap.Error(err))
			} else {
				log.Info(" Swap disabled")
			}
		}

		// Disable core dumps (optional)
		if coreDumpOff {
			if err := execute.RunSimple(rc.Ctx, "ulimit", "-c", "0"); err != nil {
				log.Warn("⚠ Failed to disable core dumps; update systemd unit with LimitCORE=0", zap.Error(err))
			} else {
				log.Info(" Core dumps disabled")
			}
		}

		//  Final reminders
		log.Info(" Reminder: Check audit device configuration and firewall rules")
		log.Info(" Reminder: Validate filesystem permissions on Vault binary and configs")

		//  Final summary
		log.Info(" Vault hardening completed",
			zap.Bool("vault_hardened", true),
		)
		return nil
	}),
}

func init() {
	SecureVaultCmd.Flags().Bool("disable-swap", false, "Disable swap on the system")
	SecureVaultCmd.Flags().Bool("disable-coredump", false, "Disable core dumps on the system")
	SecureVaultCmd.Flags().Bool("comprehensive", true, "Apply comprehensive security hardening (recommended)")
	SecureCmd.AddCommand(SecureVaultCmd)
}
