// DEPRECATED: This file is deprecated. Use 'eos bootstrap' instead of 'eos create bootstrap'.
// All bootstrap functionality has been migrated to cmd/bootstrap/ for better organization.
// This file is maintained only for backward compatibility.

package create

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	// "go.uber.org/zap"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap [component]",
	Short: "DEPRECATED: Use 'eos bootstrap' instead",
	Long: `DEPRECATED: This command is deprecated. Use 'eos bootstrap' instead.

All bootstrap functionality has been migrated to the top-level 'eos bootstrap' command:

  eos bootstrap           # Bootstrap everything (recommended)
  eos bootstrap all       # Bootstrap all components  
  eos bootstrap salt      # Bootstrap Salt infrastructure
  eos bootstrap vault     # Bootstrap Vault via Salt
  eos bootstrap nomad     # Bootstrap Nomad via Salt
  eos bootstrap osquery   # Bootstrap OSQuery
  eos bootstrap quickstart # Quick 5-minute setup

This command will redirect to the new bootstrap commands for backward compatibility.`,
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
	Long:  `Install and configure HashiCorp Vault using Salt states. Requires Salt to be already installed.`,
	RunE:  eos_cli.Wrap(runBootstrapVault),
}

var bootstrapNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Bootstrap HashiCorp Nomad",
	Long:  `Install and configure HashiCorp Nomad using Salt states. Requires Salt to be already installed.`,
	RunE:  eos_cli.Wrap(runBootstrapNomad),
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
	Long:  `Bootstrap all infrastructure components in the correct order: Salt, Vault, Nomad, OSQuery.`,
	RunE:  eos_cli.Wrap(runBootstrapAll),
}

func init() {
	// DEPRECATED: This command is deprecated. Users should use 'eos bootstrap' instead.
	// Keeping for backward compatibility but showing deprecation warnings.
	CreateCmd.AddCommand(bootstrapCmd)
	bootstrapCmd.AddCommand(bootstrapSaltCmd)
	bootstrapCmd.AddCommand(bootstrapVaultCmd)
	bootstrapCmd.AddCommand(bootstrapNomadCmd)
	bootstrapCmd.AddCommand(bootstrapOsqueryCmd)
	bootstrapCmd.AddCommand(bootstrapAllCmd)

	// Flags for Salt bootstrap
	bootstrapSaltCmd.Flags().Bool("master-mode", false, "Install as master-minion instead of masterless")
	bootstrapSaltCmd.Flags().String("master-address", "", "Salt master address (for minion mode)")
}

func runBootstrapSalt(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("DEPRECATION WARNING: 'eos create bootstrap salt' is deprecated. Use 'eos bootstrap salt' instead.")
	logger.Info("Starting Salt bootstrap with integrated file_roots setup")

	masterMode := cmd.Flag("master-mode").Value.String() == "true"

	config := &saltstack.Config{
		MasterMode: masterMode,
		LogLevel:   "warning",
	}

	logger.Info("Installing Salt and configuring file_roots for eos state management")
	if err := saltstack.Install(rc, config); err != nil {
		return err
	}

	logger.Info("Salt bootstrap completed successfully")
	logger.Info("Salt states are now accessible via file_roots configuration")
	logger.Info("Test with: salt-call --local state.show_sls dependencies")
	return nil
}

func runBootstrapVault(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("DEPRECATION WARNING: 'eos create bootstrap vault' is deprecated. Use 'eos bootstrap vault' instead.")
	logger.Info("Starting Vault bootstrap")

	// Use the Salt-based Vault deployment for architectural consistency
	if err := vault.OrchestrateVaultCreateViaSalt(rc); err != nil {
		return err
	}

	logger.Info("Vault bootstrap completed successfully")
	return nil
}

func runBootstrapNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("DEPRECATION WARNING: 'eos create bootstrap nomad' is deprecated. Use 'eos bootstrap nomad' instead.")
	logger.Info("Starting Nomad bootstrap")

	// Use the bootstrap-specific Salt deployment (no interactive prompts)
	if err := nomad.DeployNomadViaSaltBootstrap(rc); err != nil {
		return err
	}

	logger.Info("Nomad bootstrap completed successfully")
	return nil
}

func runBootstrapOsquery(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("DEPRECATION WARNING: 'eos create bootstrap osquery' is deprecated. Use 'eos bootstrap osquery' instead.")
	logger.Info("Starting OSQuery bootstrap")

	if err := osquery.InstallOsquery(rc); err != nil {
		return err
	}

	logger.Info("OSQuery bootstrap completed successfully")
	return nil
}

func runBootstrapAll(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("DEPRECATION WARNING: 'eos create bootstrap all' is deprecated. Use 'eos bootstrap all' or 'eos bootstrap' instead.")
	// Redirect to enhanced version that includes storage ops and clustering
	return RunBootstrapAllEnhanced(rc, cmd, args)
}