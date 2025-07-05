// cmd/create/grafana.go
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

// CreateGrafanaCmd installs Grafana using Docker
var CreateGrafanaCmd = &cobra.Command{
	Use:     "grafana",
	Short:   "Install Grafana monitoring and visualization platform",
	Long: `Install Grafana using Docker with comprehensive configuration options.

Grafana is a powerful monitoring and visualization platform that allows you to
query, visualize, and understand your metrics. This command sets up Grafana
with Docker and provides options for custom configuration.

Examples:
  eos create grafana                                    # Install with defaults
  eos create grafana --version 10.2.0 --port 3000     # Specific version and port
  eos create grafana --interactive                     # Interactive setup
  eos create grafana --dry-run                         # Test installation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		version, _ := cmd.Flags().GetString("version")
		port, _ := cmd.Flags().GetInt("port")
		interactive, _ := cmd.Flags().GetBool("interactive")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		skipHealthCheck, _ := cmd.Flags().GetBool("skip-health-check")

		logger.Info("Installing Grafana", 
			zap.String("version", version),
			zap.Int("port", port),
			zap.Bool("interactive", interactive),
			zap.Bool("dry_run", dryRun))

		manager := service_installation.NewServiceInstallationManager()

		// Build installation options
		options := &service_installation.ServiceInstallOptions{
			Name:            "grafana",
			Type:            service_installation.ServiceTypeGrafana,
			Version:         version,
			Port:            port,
			Method:          service_installation.MethodDocker,
			Interactive:     interactive,
			DryRun:          dryRun,
			Force:           force,
			SkipHealthCheck: skipHealthCheck,
			Environment:     make(map[string]string),
			Config:          make(map[string]string),
		}

		// Interactive mode
		if interactive {
			if err := runInteractiveGrafanaSetup(options); err != nil {
				return fmt.Errorf("interactive setup failed: %w", err)
			}
		}

		// Set defaults
		if options.Version == "" {
			options.Version = "latest"
		}
		if options.Port == 0 {
			options.Port = 3000
		}

		// Perform installation
		result, err := manager.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("grafana installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("Grafana installation completed successfully",
				zap.String("version", result.Version),
				zap.Int("port", result.Port),
				zap.Duration("duration", result.Duration))

			fmt.Printf("\n✅ Grafana Installation Complete!\n\n")
			fmt.Printf("📊 Service Details:\n")
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
					fmt.Printf("   %s: %s\n", key, value)
				}
			}

			fmt.Printf("\n📝 Next Steps:\n")
			fmt.Printf("   1. Open Grafana in your browser: http://localhost:%d\n", result.Port)
			fmt.Printf("   2. Login with default credentials (admin/admin)\n")
			fmt.Printf("   3. Change the default password\n")
			fmt.Printf("   4. Configure data sources and dashboards\n")
			fmt.Printf("   5. Check status: eos status grafana\n")
		} else {
			logger.Error("Grafana installation failed", zap.String("error", result.Error))
			fmt.Printf("\n❌ Grafana Installation Failed!\n")
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
	CreateCmd.AddCommand(CreateGrafanaCmd)

	CreateGrafanaCmd.Flags().StringP("version", "v", "latest", "Grafana version to install")
	CreateGrafanaCmd.Flags().IntP("port", "p", 3000, "Port to expose Grafana on")
	CreateGrafanaCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive setup mode")
	CreateGrafanaCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateGrafanaCmd.Flags().BoolP("force", "f", false, "Force installation even if port is in use")
	CreateGrafanaCmd.Flags().Bool("skip-health-check", false, "Skip post-installation health check")
}

var interactive bool

func runInteractiveGrafanaSetup(options *service_installation.ServiceInstallOptions) error {
	fmt.Printf("🔧 Interactive Grafana Setup\n")
	fmt.Printf("============================\n\n")

	// Version
	fmt.Printf("Grafana version [%s]: ", options.Version)
	var version string
	fmt.Scanln(&version)
	if version != "" {
		options.Version = version
	}

	// Port
	fmt.Printf("Port [%d]: ", options.Port)
	var portStr string
	fmt.Scanln(&portStr)
	if portStr != "" {
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
			options.Port = port
		}
	}

	// Admin password
	fmt.Print("Set custom admin password? [y/N]: ")
	var setPassword string
	fmt.Scanln(&setPassword)
	if setPassword == "y" || setPassword == "Y" {
		fmt.Print("Admin password: ")
		var password string
		fmt.Scanln(&password)
		if password != "" {
			options.Environment["GF_SECURITY_ADMIN_PASSWORD"] = password
		}
	}

	// Anonymous access
	fmt.Print("Enable anonymous access? [y/N]: ")
	var anonymous string
	fmt.Scanln(&anonymous)
	if anonymous == "y" || anonymous == "Y" {
		options.Environment["GF_AUTH_ANONYMOUS_ENABLED"] = "true"
		options.Environment["GF_AUTH_ANONYMOUS_ORG_ROLE"] = "Viewer"
	}

	// Persistence
	fmt.Print("Enable data persistence? [Y/n]: ")
	var persistence string
	fmt.Scanln(&persistence)
	if persistence != "n" && persistence != "N" {
		options.Volumes = append(options.Volumes, service_installation.VolumeMount{
			Source:      "grafana-data",
			Destination: "/var/lib/grafana",
		})
	}

	fmt.Printf("\n📋 Configuration Summary:\n")
	fmt.Printf("   Version: %s\n", options.Version)
	fmt.Printf("   Port: %d\n", options.Port)
	fmt.Printf("   Persistence: %t\n", len(options.Volumes) > 0)
	fmt.Printf("   Anonymous Access: %s\n", options.Environment["GF_AUTH_ANONYMOUS_ENABLED"])

	fmt.Print("\nProceed with installation? [Y/n]: ")
	var proceed string
	fmt.Scanln(&proceed)
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("installation cancelled by user")
	}

	return nil
}