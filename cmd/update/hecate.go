/* cmd/update/hecate.go */

package update

import (
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateCmd represents the "update" command.
var updateHecateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update configurations and services",
	Long: `Update Hecate configurations, renew certificates, or update specific services.

Examples:
  hecate update certs
  hecate update eos
  hecate update http
  hecate update docker-compose`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for update command.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Initialize the shared global logger.

	// Attach subcommands to UpdateCmd.
	UpdateCmd.AddCommand(runCertsCmd)
	UpdateCmd.AddCommand(runEosCmd)
	UpdateCmd.AddCommand(runHttpCmd)
	UpdateCmd.AddCommand(runK3sCmd)
}

// runK3sCmd updates the k3s deployment configuration.
var runK3sCmd = &cobra.Command{
	Use:   "k3s",
	Short: "Update k3s deployment configuration",
	Long: `Update the k3s deployment by applying updated manifests and restarting services.
This is the preferred method for managing Hecate containers.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting k3s deployment update")

		// Check if Hecate is properly set up
		if _, err := os.Stat("/opt/hecate"); os.IsNotExist(err) {
			logger.Error("Hecate installation not found")
			return fmt.Errorf("hecate not installed - run 'eos create hecate' first")
		}

		// Check if k3s is running
		checkCmd := exec.Command("kubectl", "get", "nodes")
		if err := checkCmd.Run(); err != nil {
			logger.Error("k3s cluster not accessible", zap.Error(err))
			return fmt.Errorf("k3s cluster not running - ensure k3s is installed and running")
		}

		logger.Info(" Applying updated k3s manifests")

		// Apply manifests from /opt/hecate/k3s/ directory
		applyCmd := exec.Command("kubectl", "apply", "-f", "/opt/hecate/k3s/")
		if err := applyCmd.Run(); err != nil {
			logger.Error("Failed to apply k3s manifests", zap.Error(err))
			return fmt.Errorf("failed to apply k3s manifests: %w", err)
		}

		logger.Info(" Rolling restart of hecate deployments")

		// Restart hecate namespace deployments
		restartCmd := exec.Command("kubectl", "rollout", "restart", "deployment", "-n", "hecate")
		if err := restartCmd.Run(); err != nil {
			logger.Warn("Failed to restart deployments (may not exist yet)", zap.Error(err))
		}

		logger.Info(" k3s deployment update completed successfully")
		return nil
	}),
}

// runCertsCmd renews SSL certificates.
var runCertsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Renew SSL certificates",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting certificate renewal process")

		// Check if Hecate is properly set up
		if _, err := os.Stat("/opt/hecate"); os.IsNotExist(err) {
			logger.Error("Hecate installation not found")
			return fmt.Errorf("hecate not installed - run 'eos create hecate' first")
		}

		// Try k3s first (preferred method)
		if checkCmd := exec.Command("kubectl", "get", "nodes"); checkCmd.Run() == nil {
			logger.Info(" Restarting Caddy pod in k3s to trigger certificate renewal")

			restartCmd := exec.Command("kubectl", "rollout", "restart", "deployment/caddy", "-n", "hecate")
			if err := restartCmd.Run(); err != nil {
				logger.Error("Failed to restart Caddy deployment in k3s", zap.Error(err))
				return fmt.Errorf("failed to restart Caddy in k3s: %w", err)
			}
		} else {
			// Fallback to docker compose if k3s isn't available
			logger.Info(" k3s not available, falling back to docker compose")

			if _, err := os.Stat("/opt/hecate/docker-compose.yml"); os.IsNotExist(err) {
				return fmt.Errorf("neither k3s nor docker-compose.yml found - please set up Hecate properly")
			}

			cmd := exec.Command("docker", "compose", "-f", "/opt/hecate/docker-compose.yml", "restart", "caddy")
			if err := cmd.Run(); err != nil {
				logger.Error("Failed to restart Caddy container", zap.Error(err))
				return fmt.Errorf("failed to restart Caddy: %w", err)
			}
		}

		logger.Info(" Certificate renewal triggered successfully")
		logger.Info(" Caddy will automatically renew certificates that are near expiry")
		return nil
	}),
}

// runEosCmd updates the Eos system.
var runEosCmd = &cobra.Command{
	Use:   "eos",
	Short: "Update Eos system",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting Eos system update")

		// Check if Hecate is properly set up
		if _, err := os.Stat("/opt/hecate/docker-compose.yml"); os.IsNotExist(err) {
			logger.Error("Hecate installation not found")
			return fmt.Errorf("hecate not installed - run 'eos create hecate' first")
		}

		logger.Info(" Pulling latest container images")

		// Pull latest images
		pullCmd := exec.Command("docker", "compose", "-f", "/opt/hecate/docker-compose.yml", "pull")
		if err := pullCmd.Run(); err != nil {
			logger.Error("Failed to pull latest images", zap.Error(err))
			return fmt.Errorf("failed to pull images: %w", err)
		}

		logger.Info(" Restarting services with updated images")

		// Restart services with new images
		restartCmd := exec.Command("docker", "compose", "-f", "/opt/hecate/docker-compose.yml", "up", "-d", "--force-recreate")
		if err := restartCmd.Run(); err != nil {
			logger.Error("Failed to restart services", zap.Error(err))
			return fmt.Errorf("failed to restart services: %w", err)
		}

		logger.Info(" Eos system update completed successfully")
		return nil
	}),
}

// runHttpCmd updates the HTTP server configuration.
var runHttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Update HTTP configurations",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting HTTP configuration update")

		// Check if Hecate is properly set up
		if _, err := os.Stat("/opt/hecate/docker-compose.yml"); os.IsNotExist(err) {
			logger.Error("Hecate installation not found")
			return fmt.Errorf("hecate not installed - run 'eos create hecate' first")
		}

		logger.Info(" Reloading Caddy configuration")

		// Reload Caddy configuration
		reloadCmd := exec.Command("docker", "compose", "-f", "/opt/hecate/docker-compose.yml", "exec", "caddy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile")
		if err := reloadCmd.Run(); err != nil {
			logger.Warn("Failed to reload Caddy config via exec, trying restart", zap.Error(err))
			// Fallback to restart if reload fails
			restartCmd := exec.Command("docker", "compose", "-f", "/opt/hecate/docker-compose.yml", "restart", "caddy")
			if err := restartCmd.Run(); err != nil {
				logger.Error("Failed to restart Caddy", zap.Error(err))
				return fmt.Errorf("failed to reload HTTP configuration: %w", err)
			}
		}

		logger.Info(" Reloading Nginx configuration")

		// Reload Nginx configuration
		nginxReloadCmd := exec.Command("docker", "compose", "-f", "/opt/hecate/docker-compose.yml", "exec", "nginx", "nginx", "-s", "reload")
		if err := nginxReloadCmd.Run(); err != nil {
			logger.Warn("Failed to reload Nginx config via exec, trying restart", zap.Error(err))
			// Fallback to restart if reload fails
			restartCmd := exec.Command("docker", "compose", "-f", "/opt/hecate/docker-compose.yml", "restart", "nginx")
			if err := restartCmd.Run(); err != nil {
				logger.Error("Failed to restart Nginx", zap.Error(err))
				return fmt.Errorf("failed to reload Nginx configuration: %w", err)
			}
		}

		logger.Info(" HTTP configuration update completed successfully")
		return nil
	}),
}
