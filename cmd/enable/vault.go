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
		client, err := vault.CreateVaultClient()
		if err != nil {
			return logger.LogErrAndWrap("create vault client", err)
		}

		// Step 2: Fill EnableOptions
		opts := vault.EnableOpts
		opts.AppRoleOptions = vault.DefaultAppRoleOptions()

		// Step 3: Run lifecycle orchestration
		if err := vault.EnableVault(client, log, opts); err != nil {
			return logger.LogErrAndWrap("enable vault", err)
		}

		zap.L().Info("✅ Vault setup completed successfully")
		zap.L().Info("ℹ️  Next step: run `eos secure vault` to finalize hardening")
		return nil
	}),
}

func init() {
	EnableVaultCmd.Flags().BoolVar(&vault.EnableOpts.EnableAppRole, "approle", false, "Enable AppRole authentication method")
	EnableVaultCmd.Flags().BoolVar(&vault.EnableOpts.EnableAgent, "agent", false, "Enable Vault Agent setup")
	EnableVaultCmd.Flags().BoolVar(&vault.EnableOpts.EnableAPI, "api", false, "Verify Vault API client connectivity")
	EnableVaultCmd.Flags().BoolVar(&vault.EnableOpts.NonInteractive, "non-interactive", false, "Run without interactive prompts")
	EnableVaultCmd.Flags().StringVar(&vault.EnableOpts.Password, "password", "", "EOS Vault user password (optional; fallback to prompt)")
	EnableVaultCmd.Flags().BoolVar(&vault.EnableOpts.EnableUserpass, "userpass", false, "Enable Userpass authentication method")
	EnableCmd.AddCommand(EnableVaultCmd)
}
