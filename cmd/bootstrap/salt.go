package bootstrap

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var saltCmd = &cobra.Command{
	Use:   "salt",
	Short: "Bootstrap SaltStack infrastructure",
	Long:  `Install and configure SaltStack from scratch. This will set up Salt master and minion services.`,
	RunE:  eos_cli.Wrap(runBootstrapSalt),
}

func init() {
	// Flags for Salt bootstrap
	saltCmd.Flags().Bool("master-mode", false, "Install as master-minion instead of masterless")
	saltCmd.Flags().String("master-address", "", "Salt master address (for minion mode)")
}

// GetSaltCmd returns the salt bootstrap command
func GetSaltCmd() *cobra.Command {
	return saltCmd
}

func runBootstrapSalt(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
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