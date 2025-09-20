package bootstrap

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var nomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Bootstrap HashiCorp Nomad using ",
	Long:  `Install and configure HashiCorp Nomad using  states. Requires  to be already installed.`,
	RunE:  eos_cli.Wrap(runBootstrapNomad),
}

func init() {
	// Command initialization
}

// GetNomadCmd returns the nomad bootstrap command
func GetNomadCmd() *cobra.Command {
	return nomadCmd
}

func runBootstrapNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Nomad bootstrap")

	// Use the bootstrap-specific  deployment (no interactive prompts)
	if err := nomad.DeployNomadViaBootstrap(rc); err != nil {
		return err
	}

	logger.Info("Nomad bootstrap completed successfully")
	return nil
}
