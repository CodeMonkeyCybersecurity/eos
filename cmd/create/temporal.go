// cmd/create/temporal.go
package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/temporal"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var CreateTemporalCmd = &cobra.Command{
	Use:   "temporal",
	Short: "Install production Temporal server for Iris framework",
	Long: `Install and configure production Temporal server with PostgreSQL backend.

This installs:
- PostgreSQL database (temporal + temporal_visibility)
- Temporal server with all services (frontend, matching, history, worker)
- Temporal Web UI
- Systemd service for automatic startup
- Prometheus metrics endpoint

The Temporal server provides durable workflow execution for the Iris framework
(inter-service communication hub).

Installation directory: /opt/temporal-iris
Data directory: /var/lib/temporal-iris

Examples:
  eos create temporal                    # Install with defaults
`,
	RunE: eos.Wrap(runCreateTemporal),
}

func init() {
	CreateCmd.AddCommand(CreateTemporalCmd)
}

func runCreateTemporal(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Temporal server installation for Iris framework")

	// ASSESS - Discover environment
	logger.Info("Discovering environment configuration")
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w", err)
	}

	// Initialize secret manager and generate password
	logger.Info("Initializing secret manager")
	secretManager, err := secrets.NewSecretManager(rc, envConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize secret manager: %w", err)
	}

	requiredSecrets := map[string]secrets.SecretType{
		"postgres_password": secrets.SecretTypePassword,
	}
	serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("temporal", requiredSecrets)
	if err != nil {
		return fmt.Errorf("failed to generate secrets: %w", err)
	}
	pgPassword, _ := serviceSecrets.Secrets["postgres_password"].(string)

	// INTERVENE - Install Temporal server
	logger.Info("Installing Temporal server")
	if err := temporal.InstallServer(rc.Ctx, pgPassword); err != nil {
		return fmt.Errorf("temporal installation failed: %w", err)
	}

	// EVALUATE - Display completion info
	logger.Info("Temporal server installation completed successfully")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Temporal Server Installed")
	logger.Info("terminal prompt: ==========================")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Service Management:")
	logger.Info("terminal prompt:   Start:   sudo systemctl start temporal-iris")
	logger.Info("terminal prompt:   Stop:    sudo systemctl stop temporal-iris")
	logger.Info("terminal prompt:   Status:  sudo systemctl status temporal-iris")
	logger.Info("terminal prompt:   Logs:    sudo journalctl -u temporal-iris -f")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Access:")
	logger.Info("terminal prompt:   Temporal Server: localhost:7233")
	logger.Info("terminal prompt:   Temporal UI:     http://localhost:8233")
	logger.Info("terminal prompt:   Metrics:         http://localhost:9090/metrics")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Credentials saved to: /opt/temporal-iris/.credentials")
	logger.Info("terminal prompt: ")

	return nil
}
