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

			fmt.Printf("\n✅ Apache Guacamole Installation Complete!\n\n")
			fmt.Printf("🖥️ Service Details:\n")
			fmt.Printf("   Version: %s\n", result.Version)
			fmt.Printf("   Port: %d\n", result.Port)
			fmt.Printf("   Method: %s\n", result.Method)
			fmt.Printf("   Duration: %s\n", result.Duration)

			if len(result.Endpoints) > 0 {
				fmt.Printf("\n🌐 Access URLs:\n")
				for _, endpoint := range result.Endpoints {
					fmt.Printf("   %s\n", endpoint)
				}
			}

			if len(result.Credentials) > 0 {
				fmt.Printf("\n🔐 Default Credentials:\n")
				for key, value := range result.Credentials {
					if key != "DB_PASSWORD" && key != "DB_USER" && key != "DB_NAME" {
						fmt.Printf("   %s: %s\n", key, value)
					}
				}
			}

			fmt.Printf("\n📝 Next Steps:\n")
			fmt.Printf("   1. Open Guacamole: http://localhost:%d/guacamole\n", result.Port)
			fmt.Printf("   2. Login with: guacadmin / guacadmin\n")
			fmt.Printf("   3. IMMEDIATELY change the default password\n")
			fmt.Printf("   4. Configure connections (RDP, VNC, SSH)\n")
			fmt.Printf("   5. Set up SSL/TLS for production use\n")
			fmt.Printf("   6. Check status: eos status guacamole\n")

			fmt.Printf("\n🛡️ Security Notes:\n")
			fmt.Printf("   - Change default admin credentials immediately\n")
			fmt.Printf("   - Use strong passwords for connections\n")
			fmt.Printf("   - Consider setting up reverse proxy with SSL\n")
			fmt.Printf("   - Regularly update Guacamole for security patches\n")

			fmt.Printf("\n📚 Supported Protocols:\n")
			fmt.Printf("   - RDP (Remote Desktop Protocol)\n")
			fmt.Printf("   - VNC (Virtual Network Computing)\n")
			fmt.Printf("   - SSH (Secure Shell)\n")
			fmt.Printf("   - Telnet\n")
			fmt.Printf("   - Kubernetes\n")
		} else {
			logger.Error("Apache Guacamole installation failed", zap.String("error", result.Error))
			fmt.Printf("\n❌ Apache Guacamole Installation Failed!\n")
			fmt.Printf("Error: %s\n", result.Error)

			if len(result.Steps) > 0 {
				fmt.Printf("\nInstallation Steps:\n")
				for _, step := range result.Steps {
					status := "✅"
					if step.Status == "failed" {
						status = "❌"
					} else if step.Status == "running" {
						status = "⏳"
					}
					fmt.Printf("   %s %s (%s)\n", status, step.Name, step.Duration)
					if step.Error != "" {
						fmt.Printf("      Error: %s\n", step.Error)
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