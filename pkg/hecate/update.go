package hecate

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateConfig holds configuration for Hecate update operations
type UpdateConfig struct {
	HecatePath      string
	DockerCompose   string
	K3sManifestPath string
	UseK3s          bool
}

// HecateUpdater handles Hecate update operations
type HecateUpdater struct {
	rc     *eos_io.RuntimeContext
	config *UpdateConfig
	logger otelzap.LoggerWithCtx
}

// NewHecateUpdater creates a new Hecate updater
func NewHecateUpdater(rc *eos_io.RuntimeContext, config *UpdateConfig) *HecateUpdater {
	// Set defaults
	if config.HecatePath == "" {
		config.HecatePath = "/opt/hecate"
	}
	if config.DockerCompose == "" {
		config.DockerCompose = "/opt/hecate/docker-compose.yml"
	}
	if config.K3sManifestPath == "" {
		config.K3sManifestPath = "/opt/hecate/k3s/"
	}

	return &HecateUpdater{
		rc:     rc,
		config: config,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// CheckInstallation verifies Hecate is installed
func (hu *HecateUpdater) CheckInstallation() error {
	if _, err := os.Stat(hu.config.HecatePath); os.IsNotExist(err) {
		return fmt.Errorf("hecate not installed - run 'eos create hecate' first")
	}
	return nil
}

// CheckK3s checks if k3s cluster is available
func (hu *HecateUpdater) CheckK3s() bool {
	checkCmd := exec.Command("kubectl", "get", "nodes")
	return checkCmd.Run() == nil
}

// UpdateK3sDeployment updates k3s deployment configuration
func (hu *HecateUpdater) UpdateK3sDeployment() error {
	hu.logger.Info("Starting k3s deployment update")

	// Check installation
	if err := hu.CheckInstallation(); err != nil {
		return err
	}

	// Check if k3s is running
	if !hu.CheckK3s() {
		hu.logger.Error("k3s cluster not accessible")
		return fmt.Errorf("k3s cluster not running - ensure k3s is installed and running")
	}

	hu.logger.Info("Applying updated k3s manifests")

	// Apply manifests
	applyCmd := exec.Command("kubectl", "apply", "-f", hu.config.K3sManifestPath)
	if err := applyCmd.Run(); err != nil {
		hu.logger.Error("Failed to apply k3s manifests", zap.Error(err))
		return fmt.Errorf("failed to apply k3s manifests: %w", err)
	}

	hu.logger.Info("Rolling restart of hecate deployments")

	// Restart deployments
	restartCmd := exec.Command("kubectl", "rollout", "restart", "deployment", "-n", "hecate")
	if err := restartCmd.Run(); err != nil {
		hu.logger.Warn("Failed to restart deployments (may not exist yet)", zap.Error(err))
	}

	hu.logger.Info("k3s deployment update completed successfully")
	return nil
}

// RenewCertificates triggers certificate renewal
func (hu *HecateUpdater) RenewCertificates() error {
	hu.logger.Info("Starting certificate renewal process")

	// Check installation
	if err := hu.CheckInstallation(); err != nil {
		return err
	}

	// Try k3s first (preferred method)
	if hu.CheckK3s() {
		hu.logger.Info("Restarting Caddy pod in k3s to trigger certificate renewal")

		restartCmd := exec.Command("kubectl", "rollout", "restart", "deployment/caddy", "-n", "hecate")
		if err := restartCmd.Run(); err != nil {
			hu.logger.Error("Failed to restart Caddy deployment in k3s", zap.Error(err))
			return fmt.Errorf("failed to restart Caddy in k3s: %w", err)
		}
	} else {
		// Fallback to docker compose
		hu.logger.Info("k3s not available, falling back to docker compose")

		if _, err := os.Stat(hu.config.DockerCompose); os.IsNotExist(err) {
			return fmt.Errorf("neither k3s nor docker-compose.yml found - please set up Hecate properly")
		}

		cmd := exec.Command("docker", "compose", "-f", hu.config.DockerCompose, "restart", "caddy")
		if err := cmd.Run(); err != nil {
			hu.logger.Error("Failed to restart Caddy container", zap.Error(err))
			return fmt.Errorf("failed to restart Caddy: %w", err)
		}
	}

	hu.logger.Info("Certificate renewal triggered successfully")
	hu.logger.Info("Caddy will automatically renew certificates that are near expiry")
	return nil
}

// UpdateEosSystem updates the Eos system containers
func (hu *HecateUpdater) UpdateEosSystem() error {
	hu.logger.Info("Starting Eos system update")

	// Check docker compose file
	if _, err := os.Stat(hu.config.DockerCompose); os.IsNotExist(err) {
		hu.logger.Error("Hecate installation not found")
		return fmt.Errorf("hecate not installed - run 'eos create hecate' first")
	}

	hu.logger.Info("Pulling latest container images")

	// Pull latest images
	pullCmd := exec.Command("docker", "compose", "-f", hu.config.DockerCompose, "pull")
	if err := pullCmd.Run(); err != nil {
		hu.logger.Error("Failed to pull latest images", zap.Error(err))
		return fmt.Errorf("failed to pull images: %w", err)
	}

	hu.logger.Info("Restarting services with updated images")

	// Restart services with new images
	restartCmd := exec.Command("docker", "compose", "-f", hu.config.DockerCompose, "up", "-d", "--force-recreate")
	if err := restartCmd.Run(); err != nil {
		hu.logger.Error("Failed to restart services", zap.Error(err))
		return fmt.Errorf("failed to restart services: %w", err)
	}

	hu.logger.Info("Eos system update completed successfully")
	return nil
}

// UpdateHTTPConfig updates HTTP server configurations
func (hu *HecateUpdater) UpdateHTTPConfig() error {
	hu.logger.Info("Starting HTTP configuration update")

	// Check docker compose file
	if _, err := os.Stat(hu.config.DockerCompose); os.IsNotExist(err) {
		hu.logger.Error("Hecate installation not found")
		return fmt.Errorf("hecate not installed - run 'eos create hecate' first")
	}

	// Reload Caddy configuration
	hu.logger.Info("Reloading Caddy configuration")
	if err := hu.reloadCaddy(); err != nil {
		return err
	}

	// Reload Nginx configuration
	hu.logger.Info("Reloading Nginx configuration")
	if err := hu.reloadNginx(); err != nil {
		return err
	}

	hu.logger.Info("HTTP configuration update completed successfully")
	return nil
}

// reloadCaddy reloads Caddy configuration
func (hu *HecateUpdater) reloadCaddy() error {
	reloadCmd := exec.Command("docker", "compose", "-f", hu.config.DockerCompose, "exec", "caddy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile")
	if err := reloadCmd.Run(); err != nil {
		hu.logger.Warn("Failed to reload Caddy config via exec, trying restart", zap.Error(err))

		// Fallback to restart
		restartCmd := exec.Command("docker", "compose", "-f", hu.config.DockerCompose, "restart", "caddy")
		if err := restartCmd.Run(); err != nil {
			hu.logger.Error("Failed to restart Caddy", zap.Error(err))
			return fmt.Errorf("failed to reload HTTP configuration: %w", err)
		}
	}
	return nil
}

// reloadNginx reloads Nginx configuration
func (hu *HecateUpdater) reloadNginx() error {
	nginxReloadCmd := exec.Command("docker", "compose", "-f", hu.config.DockerCompose, "exec", "nginx", "nginx", "-s", "reload")
	if err := nginxReloadCmd.Run(); err != nil {
		hu.logger.Warn("Failed to reload Nginx config via exec, trying restart", zap.Error(err))

		// Fallback to restart
		restartCmd := exec.Command("docker", "compose", "-f", hu.config.DockerCompose, "restart", "nginx")
		if err := restartCmd.Run(); err != nil {
			hu.logger.Error("Failed to restart Nginx", zap.Error(err))
			return fmt.Errorf("failed to reload Nginx configuration: %w", err)
		}
	}
	return nil
}
