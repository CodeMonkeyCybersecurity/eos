// cmd/enable/vault.go
package enable

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var EnableVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Orchestrates minimal secure runtime setup for Vault (server, approle, agent, api)",
	Long: `Connects to Vault, ensures server readiness, and selectively enables components:
AppRole auth, Vault Agent, and API client connectivity.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		// Step 1: Get client
		client, err := vault.NewClient(rc)
		if err != nil {
			return logger.LogErrAndWrap(rc, "create vault client", err)
		}

		// Step 2: Run lifecycle orchestration (fully interactive)
		if err := vault.EnableVault(rc, client, zap.L()); err != nil {
			return logger.LogErrAndWrap(rc, "enable vault", err)
		}

		otelzap.Ctx(rc.Ctx).Info("✅ Vault setup completed successfully")
		otelzap.Ctx(rc.Ctx).Info("ℹ️  Next step: run `eos secure vault` to finalize hardening")
		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableVaultCmd)
}
