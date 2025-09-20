// cmd/create/umami.go
package create

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// umamiCmd represents the Umami installation command.
var CreateUmamiCmd = &cobra.Command{
	Use:   "umami",
	Short: "Install and deploy Umami",
	Long: `Install and deploy Umami to /opt/umami by:
- Copying the Docker Compose file from eos/assets/umami-docker-compose.yml to /opt/umami
- Replacing all instances of "changeme" with a strong random alphanumeric password
- Running "docker compose up -d" to deploy
- Waiting 5 seconds and listing running containers via "docker ps"
- Informing the user to navigate to :` + strconv.Itoa(shared.PortUmami) + ` and log in with default credentials (admin/umami) and change the password immediately.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting Umami installation using Eos")

		// ASSESS - Discover environment
		logger.Info("Discovering environment configuration")
		envConfig, err := environment.DiscoverEnvironment(rc)
		if err != nil {
			return fmt.Errorf("failed to discover environment: %w", err)
		}

		// Initialize secret manager
		secretManager, err := secrets.NewSecretManager(rc, envConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize secret manager: %w", err)
		}

		// INTERVENE - Ensure the installation directory exists
		if _, err := os.Stat(shared.UmamiDir); os.IsNotExist(err) {
			logger.Warn("Installation directory does not exist; creating it",
				zap.String("path", shared.UmamiDir))
			if err := os.MkdirAll(shared.UmamiDir, shared.DirPermStandard); err != nil {
				return fmt.Errorf("failed to create installation directory: %w", err)
			}
		} else {
			logger.Info("Installation directory exists",
				zap.String("path", shared.UmamiDir))
		}

		// Prepare the Docker Compose file paths
		sourceComposeFile := "assets/umami-docker-compose.yml"
		destComposeFile := filepath.Join(shared.UmamiDir, "umami-docker-compose.yml")

		logger.Info("Copying and processing Docker Compose file",
			zap.String("source", sourceComposeFile),
			zap.String("destination", destComposeFile))

		// Read the source Docker Compose file
		data, err := os.ReadFile(sourceComposeFile)
		if err != nil {
			return fmt.Errorf("failed to read Docker Compose file from assets: %w", err)
		}

		// Generate a strong random alphanumeric password (20 characters)
		logger.Info("Generating strong random password")
		password, err := crypto.GeneratePassword(20)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}

		// Store the password using the secret manager
		requiredSecrets := map[string]secrets.SecretType{
			"database_password": secrets.SecretTypePassword,
		}
		serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("umami", requiredSecrets)
		if err != nil {
			logger.Warn("Failed to manage secrets", zap.Error(err))
		} else {
			// Override with our generated password
			serviceSecrets.Secrets["database_password"] = password
			logger.Info("Database password stored in secret manager",
				zap.String("backend", serviceSecrets.Backend))
		}

		// Replace all occurrences of "changeme" with the generated password
		newData := strings.ReplaceAll(string(data), "changeme", password)
		logger.Info("Replaced 'changeme' with a generated password")

		// Write the processed Docker Compose file to the destination directory
		if err := os.WriteFile(destComposeFile, []byte(newData), 0644); err != nil {
			return fmt.Errorf("failed to write processed Docker Compose file: %w", err)
		}
		logger.Info("Docker Compose file processed and copied successfully")

		// Check if arachne-net docker network exists, creating it if not
		if err := container.EnsureArachneNetwork(rc); err != nil {
			return fmt.Errorf("error checking or creating 'arachne-net': %w", err)
		} else {
			logger.Info("Successfully ensured 'arachne-net' exists")
		}

		// Deploy Umami with Docker Compose using the processed file
		logger.Info("Deploying Umami with Docker Compose",
			zap.String("directory", shared.UmamiDir))
		if err := execute.RunSimple(rc.Ctx, shared.UmamiDir, "docker", "compose", "-f", destComposeFile, "up", "-d"); err != nil {
			return fmt.Errorf("error running 'docker compose up -d': %w", err)
		}

		// Wait 5 seconds for the containers to start
		logger.Info("Waiting 5 seconds for containers to initialize...")
		time.Sleep(5 * time.Second)

		// EVALUATE - Execute "docker ps" to list running containers
		if err := container.CheckDockerContainers(rc); err != nil {
			return fmt.Errorf("error checking running Docker containers: %w", err)
		}

		// Display success information
		logger.Info("Environment discovered",
			zap.String("environment", envConfig.Environment),
			zap.String("datacenter", envConfig.Datacenter),
			zap.String("vault_addr", envConfig.VaultAddr))

		logger.Info("Umami is now available",
			zap.String("web_ui", fmt.Sprintf("http://%s:%d", eos_unix.GetInternalHostname(), shared.PortUmami)),
			zap.String("username", "admin"),
			zap.String("password", "umami"),
			zap.String("note", "Change password immediately after first login"))

		logger.Info("Configuration details",
			zap.String("database_password", "Stored in secret manager at umami/database_password"),
			zap.String("docker_network", "arachne-net"),
			zap.String("config_location", destComposeFile))

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateUmamiCmd)

}
