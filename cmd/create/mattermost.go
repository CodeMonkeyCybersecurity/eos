// cmd/create/mattermost.go
//
// Orchestration-only command for deploying Mattermost.
// All business logic is in pkg/mattermost/install.go.
package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/mattermost"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateMattermostCmd installs Mattermost team collaboration platform.
var CreateMattermostCmd = &cobra.Command{
	Use:   "mattermost",
	Short: "Install Mattermost team collaboration platform",
	Long: `Deploy Mattermost using Docker Compose with automatic configuration.

This command provides a complete Mattermost deployment:
- Docker Compose orchestration (PostgreSQL + Mattermost)
- Secure credential generation and Vault storage
- Automatic environment discovery
- Idempotent: safe to run multiple times

Examples:
  eos create mattermost                                  # Deploy with defaults
  eos create mattermost --database-password mypass       # Override DB password
  eos create mattermost --port 8065                      # Override port
  eos create mattermost --dry-run                        # Preview without deploying`,

	RunE: eos.Wrap(runCreateMattermost),
}

func init() {
	CreateCmd.AddCommand(CreateMattermostCmd)

	CreateMattermostCmd.Flags().String("database-password", "", "Override automatic database password generation")
	CreateMattermostCmd.Flags().IntP("port", "p", mattermost.DefaultPort, "Host port for Mattermost")
	CreateMattermostCmd.Flags().Bool("dry-run", false, "Preview changes without applying")
}

func runCreateMattermost(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (sudo eos create mattermost)")
	}

	// Parse flags into config
	cfg := mattermost.DefaultInstallConfig()

	dryRun, err := cmd.Flags().GetBool("dry-run")
	if err != nil {
		return fmt.Errorf("parse --dry-run: %w", err)
	}
	cfg.DryRun = dryRun

	if cmd.Flags().Changed("port") {
		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			return fmt.Errorf("parse --port: %w", err)
		}
		cfg.Port = port
	}

	// Get database password: flag -> secrets manager -> auto-generate
	if cmd.Flags().Changed("database-password") {
		dbPass, err := cmd.Flags().GetString("database-password")
		if err != nil {
			return fmt.Errorf("parse --database-password: %w", err)
		}
		cfg.PostgresPassword = dbPass
		logger.Info("Using database password from --database-password flag")
	} else {
		// Use secrets manager to generate/retrieve password
		password, err := getOrGeneratePassword(rc, logger)
		if err != nil {
			logger.Warn("Secrets manager unavailable, password will be set from .env template",
				zap.Error(err))
		} else {
			cfg.PostgresPassword = password
		}
	}

	// Delegate all business logic to pkg/mattermost
	return mattermost.Install(rc, cfg)
}

// getOrGeneratePassword uses the secrets manager to get or generate the DB password.
func getOrGeneratePassword(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) (string, error) {
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return "", fmt.Errorf("environment discovery failed: %w", err)
	}

	secretManager, err := secrets.NewManager(rc, envConfig)
	if err != nil {
		return "", fmt.Errorf("secret manager init failed: %w", err)
	}

	requiredSecrets := map[string]secrets.SecretType{
		"database_password": secrets.SecretTypePassword,
	}

	serviceSecrets, err := secretManager.EnsureServiceSecrets(rc.Ctx, mattermost.ServiceName, requiredSecrets)
	if err != nil {
		return "", fmt.Errorf("secret generation failed: %w", err)
	}

	password, ok := serviceSecrets.Secrets["database_password"].(string)
	if !ok || password == "" {
		return "", fmt.Errorf("generated password is empty")
	}

	logger.Info("Database password managed by secrets manager",
		zap.String("backend", serviceSecrets.Backend))

	return password, nil
}
