package create

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap [component]",
	Short: "Bootstrap infrastructure components from scratch",
	Long: `Bootstrap infrastructure components on a fresh system.
This command installs and configures core infrastructure without requiring Salt.

Available components:
  salt     - Install and configure Salt (master/minion or masterless)
  vault    - Install and configure HashiCorp Vault
  osquery  - Install and configure OSQuery for system monitoring
  all      - Bootstrap all components in the correct order

Examples:
  eos create bootstrap salt      # Bootstrap Salt infrastructure
  eos create bootstrap vault     # Bootstrap Vault (requires Salt)
  eos create bootstrap all       # Bootstrap everything`,
}

var bootstrapSaltCmd = &cobra.Command{
	Use:   "salt",
	Short: "Bootstrap SaltStack infrastructure",
	Long:  `Install and configure SaltStack from scratch. This will set up Salt master and minion services.`,
	RunE:  eos_cli.Wrap(runBootstrapSalt),
}

var bootstrapVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Bootstrap HashiCorp Vault",
	Long:  `Install and configure HashiCorp Vault. Requires Salt to be already installed.`,
	RunE:  eos_cli.Wrap(runBootstrapVault),
}

var bootstrapOsqueryCmd = &cobra.Command{
	Use:   "osquery",
	Short: "Bootstrap OSQuery for system monitoring",
	Long:  `Install and configure OSQuery for out-of-band system state verification.`,
	RunE:  eos_cli.Wrap(runBootstrapOsquery),
}

var bootstrapAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Bootstrap all infrastructure components",
	Long:  `Bootstrap all infrastructure components in the correct order: Salt, Vault, OSQuery.`,
	RunE:  eos_cli.Wrap(runBootstrapAll),
}

func init() {
	CreateCmd.AddCommand(bootstrapCmd)
	bootstrapCmd.AddCommand(bootstrapSaltCmd)
	bootstrapCmd.AddCommand(bootstrapVaultCmd)
	bootstrapCmd.AddCommand(bootstrapOsqueryCmd)
	bootstrapCmd.AddCommand(bootstrapAllCmd)

	// Flags for Salt bootstrap
	bootstrapSaltCmd.Flags().Bool("master-mode", false, "Install as master-minion instead of masterless")
	bootstrapSaltCmd.Flags().String("master-address", "", "Salt master address (for minion mode)")
}

func runBootstrapSalt(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Salt bootstrap")

	config := &bootstrap.SaltConfig{
		MasterMode:    cmd.Flag("master-mode").Value.String() == "true",
		MasterAddress: cmd.Flag("master-address").Value.String(),
	}

	if err := bootstrap.BootstrapSalt(rc, config); err != nil {
		return err
	}

	logger.Info("Salt bootstrap completed successfully")
	return nil
}

func runBootstrapVault(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault bootstrap")

	if err := bootstrap.BootstrapVault(rc); err != nil {
		return err
	}

	logger.Info("Vault bootstrap completed successfully")
	return nil
}

func runBootstrapOsquery(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting OSQuery bootstrap")

	if err := bootstrap.BootstrapOSQuery(rc); err != nil {
		return err
	}

	logger.Info("OSQuery bootstrap completed successfully")
	return nil
}

func runBootstrapAll(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting full infrastructure bootstrap")

	// Bootstrap in order: Salt -> Vault -> OSQuery
	logger.Info("Phase 1: Bootstrapping Salt", zap.Int("phase", 1), zap.Int("total_phases", 3))
	if err := bootstrap.BootstrapSalt(rc, &bootstrap.SaltConfig{MasterMode: true}); err != nil {
		return err
	}

	logger.Info("Phase 2: Bootstrapping Vault", zap.Int("phase", 2), zap.Int("total_phases", 3))
	if err := bootstrap.BootstrapVault(rc); err != nil {
		return err
	}

	logger.Info("Phase 3: Bootstrapping OSQuery", zap.Int("phase", 3), zap.Int("total_phases", 3))
	if err := bootstrap.BootstrapOSQuery(rc); err != nil {
		return err
	}

	logger.Info("Full infrastructure bootstrap completed successfully")
	return nil
}