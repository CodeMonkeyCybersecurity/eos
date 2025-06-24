// cmd/create/docker.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateDockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Install Docker and configure it for non-root usage",
	Long:  "Installs Docker CE, sets up repo and user permissions, and verifies with hello-world.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting Docker installation process")

		// Require root privileges for installation
		eos_unix.RequireRoot(rc.Ctx)

		// Update package repositories first
		logger.Info(" Updating package repositories")
		if err := platform.PackageUpdate(rc, false); err != nil {
			logger.Warn("Package update failed", zap.Error(err))
			// Continue anyway as this might not be critical
		}

		// Use the comprehensive Docker installation from container package
		if err := container.InstallDocker(rc); err != nil {
			logger.Error(" Docker installation failed", zap.Error(err))
			return cerr.Wrap(err, "install Docker")
		}

		logger.Info(" Docker installation and configuration completed successfully")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateDockerCmd)
}
