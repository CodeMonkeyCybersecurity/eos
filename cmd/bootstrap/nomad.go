package bootstrap

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var nomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Bootstrap HashiCorp Nomad using SaltStack",
	Long:  `Install and configure HashiCorp Nomad using Salt states. Requires Salt to be already installed.`,
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

	// Use the bootstrap-specific Salt deployment (no interactive prompts)
	if err := nomad.DeployNomadViaSaltBootstrap(rc); err != nil {
		return err
	}

	logger.Info("Nomad bootstrap completed successfully")
	return nil
}