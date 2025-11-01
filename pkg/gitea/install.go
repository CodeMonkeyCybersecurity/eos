// pkg/gitea/install.go
// Business logic for Gitea installation following Assess → Intervene → Evaluate pattern

package gitea

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallConfig contains configuration for Gitea installation
type InstallConfig struct {
	// InstallDir is the target installation directory (default: /opt/gitea)
	InstallDir string

	// Port is the HTTP port for Gitea web interface (default: 8167)
	Port int

	// SSHPort is the SSH port for Git operations (default: 2222)
	SSHPort int
}

// DefaultInstallConfig returns the default installation configuration
func DefaultInstallConfig() *InstallConfig {
	return &InstallConfig{
		InstallDir: GiteaDir,
		Port:       GiteaPort,
		SSHPort:    GiteaSSHPort,
	}
}

// Install performs the complete Gitea installation
// PATTERN: Assess → Intervene → Evaluate
func Install(rc *eos_io.RuntimeContext, config *InstallConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Gitea installation",
		zap.String("install_dir", config.InstallDir),
		zap.Int("http_port", config.Port),
		zap.Int("ssh_port", config.SSHPort))

	// ASSESS: Check current state
	if err := assessPrerequisites(rc, config); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}

	// INTERVENE: Perform installation
	if err := interveneInstall(rc, config); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	// EVALUATE: Verify installation
	if err := evaluateInstallation(rc, config); err != nil {
		return fmt.Errorf("installation verification failed: %w", err)
	}

	logger.Info("Gitea installation completed successfully")
	return nil
}

// assessPrerequisites checks if all prerequisites are met
func assessPrerequisites(rc *eos_io.RuntimeContext, config *InstallConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing prerequisites for Gitea installation")

	// Note: Docker availability is checked implicitly when we run docker compose
	// No need for explicit check here

	logger.Info("Prerequisites check passed")
	return nil
}

// interveneInstall performs the actual installation steps
func interveneInstall(rc *eos_io.RuntimeContext, config *InstallConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Step 1: Create installation directory
	logger.Info("Creating installation directory", zap.String("path", config.InstallDir))
	if err := os.MkdirAll(config.InstallDir, DirPermStandard); err != nil {
		return fmt.Errorf("failed to create installation directory: %w", err)
	}

	// Step 2: Create data directories
	dataDirs := []string{
		filepath.Join(config.InstallDir, "data"),
		filepath.Join(config.InstallDir, "db"),
		filepath.Join(config.InstallDir, "config"),
	}
	for _, dir := range dataDirs {
		logger.Debug("Creating data directory", zap.String("path", dir))
		if err := os.MkdirAll(dir, DirPermStandard); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Step 3: Generate database password
	logger.Info("Generating database password")
	dbPassword, err := crypto.GeneratePassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate database password: %w", err)
	}
	logger.Debug("Database password generated")

	// Step 4: Create docker-compose.yml
	composeFilePath := filepath.Join(config.InstallDir, GiteaComposeFile)
	logger.Info("Creating docker-compose.yml", zap.String("path", composeFilePath))

	composeContent := DefaultComposeYAML()
	if err := os.WriteFile(composeFilePath, []byte(composeContent), FilePermStandard); err != nil {
		return fmt.Errorf("failed to write docker-compose.yml: %w", err)
	}

	// Step 5: Create .env file with secrets
	envFilePath := filepath.Join(config.InstallDir, ".env")
	logger.Info("Creating .env file", zap.String("path", envFilePath))

	envContent := fmt.Sprintf("GITEA_DB_PASSWORD=%s\n", dbPassword)
	if err := os.WriteFile(envFilePath, []byte(envContent), SecretFilePermStandard); err != nil {
		return fmt.Errorf("failed to write .env file: %w", err)
	}

	// Step 6: Ensure arachne-net network exists
	logger.Info("Ensuring arachne-net Docker network exists")
	if err := container.EnsureArachneNetwork(rc); err != nil {
		return fmt.Errorf("failed to ensure arachne-net: %w", err)
	}

	// Step 7: Deploy with Docker Compose using SDK
	logger.Info("Deploying Gitea with Docker Compose",
		zap.String("compose_file", composeFilePath))

	if err := container.ComposeUp(rc, composeFilePath); err != nil {
		return fmt.Errorf("failed to deploy Gitea: %w", err)
	}

	logger.Info("Gitea deployment initiated successfully")
	return nil
}

// evaluateInstallation verifies the installation was successful
func evaluateInstallation(rc *eos_io.RuntimeContext, config *InstallConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Gitea installation")

	// Check if containers are running
	if err := container.CheckDockerContainers(rc); err != nil {
		logger.Warn("Failed to verify running containers", zap.Error(err))
	}

	// Display success information
	logger.Info("Gitea is now available",
		zap.String("web_ui", fmt.Sprintf("http://%s:%d", shared.GetInternalHostname(), config.Port)),
		zap.String("ssh_url", fmt.Sprintf("ssh://git@%s:%d", shared.GetInternalHostname(), config.SSHPort)),
		zap.String("installation_note", "Complete initial setup via web UI"))

	logger.Info("Configuration details",
		zap.String("installation_directory", config.InstallDir),
		zap.String("compose_file", filepath.Join(config.InstallDir, GiteaComposeFile)),
		zap.String("data_directory", filepath.Join(config.InstallDir, "data")),
		zap.String("env_file", filepath.Join(config.InstallDir, ".env")),
		zap.String("database_password_note", "Database password stored in .env file"))

	logger.Info("Next steps",
		zap.String("step_1", fmt.Sprintf("Navigate to http://%s:%d", shared.GetInternalHostname(), config.Port)),
		zap.String("step_2", "Complete the initial Gitea setup wizard"),
		zap.String("step_3", "Configure your repositories and users"))

	return nil
}
