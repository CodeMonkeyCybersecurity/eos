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
	Short: "Orchestrates comprehensive Vault setup with AppRole authentication and Agent configuration",
	Long: `Connects to Vault server and configures complete runtime environment including:

• AppRole Authentication: Creates role with consistent naming and policy binding
• Vault Agent: Configures agent with systemd integration and runtime directories  
• TLS Security: Ensures CA certificate validation before agent startup
• Policy Management: Applies role-based access control with principle of least privilege
• Service Integration: Sets up systemd services with proper tmpfiles.d configuration

The command handles all authentication methods, agent lifecycle management, and 
provides comprehensive error handling with detailed troubleshooting guidance.`,
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

		otelzap.Ctx(rc.Ctx).Info(" Vault setup completed successfully")
		otelzap.Ctx(rc.Ctx).Info(" Configured: AppRole authentication, Vault Agent with systemd integration, and TLS security")
		otelzap.Ctx(rc.Ctx).Info("  Next step: run `eos secure vault` to finalize hardening")
		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableVaultCmd)
}
