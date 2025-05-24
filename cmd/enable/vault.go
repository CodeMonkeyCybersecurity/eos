// cmd/enable/vault.go
package enable

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var EnableVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Orchestrates minimal secure runtime setup for Vault (server, approle, agent, api)",
	Long: `Connects to Vault, ensures server readiness, and selectively enables components:
AppRole auth, Vault Agent, and API client connectivity.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("cmd/enable/vault")

		// Step 1: Get client
		client, err := vault.NewClient()
		if err != nil {
			return logger.LogErrAndWrap("create vault client", err)
		}

		// Step 2: Run lifecycle orchestration (fully interactive)
		if err := vault.EnableVault(client, log); err != nil {
			return logger.LogErrAndWrap("enable vault", err)
		}

		zap.L().Info("✅ Vault setup completed successfully")
		zap.L().Info("ℹ️  Next step: run `eos secure vault` to finalize hardening")
		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableVaultCmd)
}
