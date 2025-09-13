package bootstrap

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Bootstrap HashiCorp Vault using SaltStack",
	Long:  `Install and configure HashiCorp Vault using Salt states. Requires Salt to be already installed.`,
	RunE:  eos_cli.Wrap(runBootstrapVault),
}

func init() {
	// Command initialization
}

// GetVaultCmd returns the vault bootstrap command
func GetVaultCmd() *cobra.Command {
	return vaultCmd
}

func runBootstrapVault(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault bootstrap")

	// Use the Salt-based Vault deployment for architectural consistency
	if err := vault.OrchestrateVaultCreateViaNomad(rc); err != nil {
		return err
	}

	logger.Info("Vault bootstrap completed successfully")
	return nil
}