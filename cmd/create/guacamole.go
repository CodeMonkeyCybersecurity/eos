// cmd/create/guacamole.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/service_installation"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateGuacamoleCmd installs Apache Guacamole remote desktop gateway
var CreateGuacamoleCmd = &cobra.Command{
	Use:   "guacamole",
	Short: "Install Apache Guacamole remote desktop gateway",
	Long: `Install Apache Guacamole using Docker Compose for clientless remote desktop access.

Apache Guacamole is a clientless remote desktop gateway that supports standard
protocols like VNC, RDP, and SSH. It provides access to your desktop environments
from anywhere with just a web browser.

Examples:
  eos create guacamole                    # Install with defaults
  eos create guacamole --port 8080       # Custom port
  eos create guacamole --dry-run         # Test installation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		version, _ := cmd.Flags().GetString("version")
		port, _ := cmd.Flags().GetInt("port")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		workDir, _ := cmd.Flags().GetString("work-dir")

		logger.Info("Installing Apache Guacamole",
			zap.String("version", version),
			zap.Int("port", port),
			zap.Bool("dry_run", dryRun))

		manager := service_installation.NewServiceInstallationManager()

		// Build installation options
		options := &service_installation.ServiceInstallOptions{
			Name:             "guacamole",
			Type:             service_installation.ServiceTypeGuacamole,
			Version:          version,
			Port:             port,
			Method:           service_installation.MethodCompose,
			DryRun:           dryRun,
			WorkingDirectory: workDir,
			Environment:      make(map[string]string),
			Config:           make(map[string]string),
		}

		// Set defaults
		if options.Version == "" {
			options.Version = "latest"
		}
		if options.Port == 0 {
			options.Port = 8080
		}

		// Perform installation
		result, err := manager.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("guacamole installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("Apache Guacamole installation completed successfully",
				zap.String("version", result.Version),
				zap.Int("port", result.Port),
				zap.Duration("duration", result.Duration))

			logger.Info("terminal prompt: Apache Guacamole Installation Complete!\n")
			logger.Info("terminal prompt:  Service Details:")
			logger.Info("terminal prompt:    Version: %s", result.Version)
			logger.Info("terminal prompt:    Port: %d", result.Port)
			logger.Info("terminal prompt:    Method: %s", result.Method)
			logger.Info("terminal prompt:    Duration: %s", result.Duration)

			if len(result.Endpoints) > 0 {
				logger.Info("terminal prompt: 🌐 Access URLs:")
				for _, endpoint := range result.Endpoints {
					logger.Info("terminal prompt:    %s", endpoint)
				}
			}

			if len(result.Credentials) > 0 {
				logger.Info("terminal prompt:  Default Credentials:")
				for key, value := range result.Credentials {
					if key != "DB_PASSWORD" && key != "DB_USER" && key != "DB_NAME" {
						logger.Info("terminal prompt:    %s: %s", key, value)
					}
				}
			}

			logger.Info("terminal prompt: 📝 Next Steps:")
			logger.Info("terminal prompt:    1. Open Guacamole: http://localhost:%d/guacamole", result.Port)
			logger.Info("terminal prompt:    2. Login with: guacadmin / guacadmin")
			logger.Info("terminal prompt:    3. IMMEDIATELY change the default password")
			logger.Info("terminal prompt:    4. Configure connections (RDP, VNC, SSH)")
			logger.Info("terminal prompt:    5. Set up SSL/TLS for production use")
			logger.Info("terminal prompt:    6. Check status: eos status guacamole")

			logger.Info("terminal prompt: 🛡️ Security Notes:")
			logger.Info("terminal prompt:    - Change default admin credentials immediately")
			logger.Info("terminal prompt:    - Use strong passwords for connections")
			logger.Info("terminal prompt:    - Consider setting up reverse proxy with SSL")
			logger.Info("terminal prompt:    - Regularly update Guacamole for security patches")

			logger.Info("terminal prompt: 📚 Supported Protocols:")
			logger.Info("terminal prompt:    - RDP (Remote Desktop Protocol)")
			logger.Info("terminal prompt:    - VNC (Virtual Network Computing)")
			logger.Info("terminal prompt:    - SSH (Secure Shell)")
			logger.Info("terminal prompt:    - Telnet")
			logger.Info("terminal prompt:    - Kubernetes")
		} else {
			logger.Error("Apache Guacamole installation failed", zap.String("error", result.Error))
			logger.Info("terminal prompt: ❌ Apache Guacamole Installation Failed!")
			logger.Info("terminal prompt: Error: %s", result.Error)

			if len(result.Steps) > 0 {
				logger.Info("terminal prompt: Installation Steps:")
				for _, step := range result.Steps {
					status := ""
					switch step.Status {
					case "failed":
						status = "❌"
					case "running":
						status = "⏳"
					}
					logger.Info("terminal prompt:    %s %s (%s)", status, step.Name, step.Duration)
					if step.Error != "" {
						logger.Info("terminal prompt:       Error: %s", step.Error)
					}
				}
			}
		}

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateGuacamoleCmd)

	CreateGuacamoleCmd.Flags().StringP("version", "v", "latest", "Guacamole version to install")
	CreateGuacamoleCmd.Flags().IntP("port", "p", 8080, "Port to expose Guacamole on")
	CreateGuacamoleCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateGuacamoleCmd.Flags().String("work-dir", "", "Working directory for Guacamole installation")
}
