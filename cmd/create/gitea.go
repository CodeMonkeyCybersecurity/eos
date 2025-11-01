// cmd/create/gitea.go
// Orchestration for Gitea installation command

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/gitea"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CreateGiteaCmd represents the Gitea installation command
var CreateGiteaCmd = &cobra.Command{
	Use:   "gitea",
	Short: "Install and deploy Gitea Git service",
	Long: `Install and deploy Gitea Git service with PostgreSQL backend.

Gitea is a lightweight self-hosted Git service with a web interface.

This command will:
- Create installation directory at /opt/gitea
- Generate secure database credentials in .env file
- Create docker-compose.yml configuration
- Deploy Gitea and PostgreSQL containers
- Expose Gitea on port 8167 (HTTP) and 2222 (SSH)

Example:
  eos create gitea

After installation, access Gitea at http://localhost:8167 and complete
the initial setup wizard.

NOTE: Database credentials are stored in /opt/gitea/.env
      (Vault integration coming in ~6 months)`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting Gitea installation")

		// Create installation configuration
		config := gitea.DefaultInstallConfig()

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
