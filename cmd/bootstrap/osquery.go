package bootstrap

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var osqueryCmd = &cobra.Command{
	Use:   "osquery",
	Short: "Bootstrap OSQuery for system monitoring",
	Long:  `Install and configure OSQuery for out-of-band system state verification.`,
	RunE:  eos_cli.Wrap(runBootstrapOsquery),
}

func init() {
	// Command initialization
}

// GetOsqueryCmd returns the osquery bootstrap command
func GetOsqueryCmd() *cobra.Command {
	return osqueryCmd
}

func runBootstrapOsquery(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting OSQuery bootstrap")

	if err := osquery.InstallOsquery(rc); err != nil {
		return err
	}

	logger.Info("OSQuery bootstrap completed successfully")
	return nil
}