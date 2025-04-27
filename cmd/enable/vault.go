// cmd/enable/vault.go
package enable

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
)

// EnableVaultCmd initializes, unseals, and enables Vault for EOS.
var EnableVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Initializes, unseals, and enables Vault (TLS, AppRole, and EOS policy)",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("enable-vault")

		log.Info("🔌 Connecting to Vault")
		client, err := vault.EnsureVaultReady(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "connect vault", err)
		}

		log.Info("🚀 Starting Vault enable lifecycle")
		password := ""
		if err := vault.EnableVault(client, log, password); err != nil {
			return logger.LogErrAndWrap(log, "enable vault", err)
		}

		log.Info("✅ Vault fully enabled and ready for secure use")
		log.Info("ℹ️  Next step: run `eos secure vault` to finalize hardening")
		return nil
	}),
}

func init() {
	EnableVaultCmd.Flags().Bool("non-interactive", false, "Run without interactive prompts")
	EnableCmd.AddCommand(EnableVaultCmd)
}
