// cmd/create/gitea.go
// Orchestration for Gitea installation command

package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/gitea"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateGiteaCmd represents the Gitea installation command
var CreateGiteaCmd = &cobra.Command{
	Use:   "gitea",
	Short: "Install and deploy Gitea Git service",
	Long: `Install and deploy Gitea Git service with PostgreSQL backend.

Gitea is a lightweight self-hosted Git service with a web interface.

This command will:
- Create installation directory at /opt/gitea
- Generate secure database credentials
- Create docker-compose.yml configuration
- Deploy Gitea and PostgreSQL containers
- Expose Gitea on port 8167 (HTTP) and 2222 (SSH)

Example:
  eos create gitea

After installation, access Gitea at http://localhost:8167 and complete
the initial setup wizard.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting Gitea installation")

		// ASSESS: Discover environment
		logger.Info("Discovering environment configuration")
		envConfig, err := environment.DiscoverEnvironment(rc)
		if err != nil {
			return fmt.Errorf("failed to discover environment: %w", err)
		}

		logger.Info("Environment discovered",
			zap.String("environment", envConfig.Environment),
			zap.String("datacenter", envConfig.Datacenter))

		// Initialize secret manager
		logger.Info("Initializing secret manager")
		secretManager, err := secrets.NewManager(rc, envConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize secret manager: %w", err)
		}

		// Create installation configuration
		config := gitea.DefaultInstallConfig(secretManager)

		// INTERVENE: Delegate to pkg/gitea for business logic
		if err := gitea.Install(rc, config); err != nil {
			return fmt.Errorf("gitea installation failed: %w", err)
		}

		logger.Info("Gitea installation completed successfully")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateGiteaCmd)
}
