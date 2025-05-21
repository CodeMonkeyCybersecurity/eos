package nginx

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debian"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
)

//
//---------------------------- NGINX FUNCTIONS ---------------------------- //
//

// DeployApp deploys an application by copying necessary configs and restarting services
func DeployApp(app string, cmd *cobra.Command) error {
	zap.L().Info("Starting deployment", zap.String("app", app)) // ✅ Use zap.L().Info directly
	fmt.Printf("Deploying %s...\n", app)                        // 👈 Added for user visibility

	// Check if the required HTTP config exists
	httpConfig := filepath.Join(AssetsPath, "servers", app+".conf")
	if !debian.Exists(httpConfig) {
		zap.L().Error("Missing HTTP config file", zap.String("file", httpConfig))
		return fmt.Errorf("missing Nginx HTTP config for %s", app)
	}

	// Copy HTTP config
	if err := debian.CopyFile(httpConfig, filepath.Join(NginxConfPath, app+".conf"), 0); err != nil {
		return fmt.Errorf("failed to copy HTTP config: %w", err)
	}

	// Copy Stream config if available
	streamConfig := filepath.Join(AssetsPath, "stream", app+".conf")
	if debian.Exists(streamConfig) {
		if err := debian.CopyFile(streamConfig, filepath.Join(NginxStreamPath, app+".conf"), 0); err != nil {
			return fmt.Errorf("failed to copy Stream config: %w", err)
		}
	}

	// Handle NextCloud Coturn deployment
	if app == "nextcloud" {
		noTalk, _ := cmd.Flags().GetBool("without-talk")
		if !noTalk {
			zap.L().Info("Deploying Coturn for NextCloud Talk")
			if err := docker.RunDockerComposeAllServices(DefaultComposeYML, "coturn"); err != nil {
				return fmt.Errorf("failed to deploy Coturn: %w", err)
			}
		} else {
			zap.L().Info("Skipping Coturn deployment")
		}
	}

	// Validate and restart Nginx
	if err := ValidateNginx(); err != nil {
		return fmt.Errorf("invalid Nginx configuration: %w", err)
	}

	if err := RestartNginx(); err != nil {
		return fmt.Errorf("failed to restart Nginx: %w", err)
	}

	zap.L().Info("Deployment successful", zap.String("app", app))
	fmt.Printf("Successfully deployed %s!\n", app)
	return nil
}

// ValidateNginx runs `nginx -t` to check configuration validity
func ValidateNginx() error {
	zap.L().Info("Validating Nginx configuration...")
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput() // Capture full output
	fmt.Println(string(output))         // Print to console for visibility

	if err != nil {
		zap.L().Error("Nginx configuration validation failed",
			zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("nginx validation failed: %s", output)
	}
	zap.L().Info("Nginx configuration is valid", zap.String("output", "\n"+string(output)))
	return nil
}

// RestartNginx reloads the Nginx service
func RestartNginx() error {
	zap.L().Info("Restarting Nginx...")
	cmd := exec.Command("systemctl", "reload", "nginx")
	output, err := cmd.CombinedOutput() // Capture full output
	fmt.Println(string(output))         // Print to console

	if err != nil {
		zap.L().Error("Failed to restart Nginx",
			zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("nginx reload failed: %s", output)
	}
	zap.L().Info("Nginx restarted successfully", zap.String("output", "\n"+string(output)))
	return nil
}
