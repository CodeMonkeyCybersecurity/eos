// cmd/wazuh/create/docker-listener.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/dockerlistener"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var DockerListenerCmd = &cobra.Command{
	Use:   "docker-listener",
	Short: "Installs and configures the Wazuh DockerListener for Wazuh",
	Long:  "Sets up a Python virtual environment and configures Wazuh's DockerListener integration.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Setting up Wazuh DockerListener...")

		if err := dockerlistener.Setup(rc); err != nil {
			logger.Error(" DockerListener setup failed", zap.Error(err))
			return err
		}

		logger.Info(" DockerListener setup complete.")
		return nil
	}),
}
