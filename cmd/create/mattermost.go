// cmd/create/mattermost.go
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

// CreateMattermostCmd installs Mattermost team collaboration platform
var CreateMattermostCmd = &cobra.Command{
	Use:   "mattermost",
	Short: "Install Mattermost team collaboration platform",
	Long: `Install Mattermost using Docker Compose for team messaging and collaboration.

Mattermost is an open-source, self-hostable online chat service with file sharing,
search, and integrations. It is designed as an internal chat for organizations
and companies.

Examples:
  eos create mattermost                    # Install with defaults
  eos create mattermost --port 8065       # Custom port
  eos create mattermost --interactive     # Interactive setup
  eos create mattermost --dry-run         # Test installation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		version, _ := cmd.Flags().GetString("version")
		port, _ := cmd.Flags().GetInt("port")
		interactive, _ := cmd.Flags().GetBool("interactive")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		workDir, _ := cmd.Flags().GetString("work-dir")

		logger.Info("Installing Mattermost",
			zap.String("version", version),
			zap.Int("port", port),
			zap.Bool("interactive", interactive),
			zap.Bool("dry_run", dryRun))

		manager := service_installation.NewServiceInstallationManager()

		// Build installation options
		options := &service_installation.ServiceInstallOptions{
			Name:             "mattermost",
			Type:             service_installation.ServiceTypeMattermost,
			Version:          version,
			Port:             port,
			Method:           service_installation.MethodCompose,
			Interactive:      interactive,
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
			options.Port = 8065
		}

		// Interactive mode
		if interactive {
			if err := runInteractiveMattermostSetup(options); err != nil {
				return fmt.Errorf("interactive setup failed: %w", err)
			}
		}

		// Perform installation
		result, err := manager.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("mattermost installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("Mattermost installation completed successfully",
				zap.String("version", result.Version),
				zap.Int("port", result.Port),
				zap.Duration("duration", result.Duration))

			fmt.Printf("\nMattermost Installation Complete!\n\n")
			fmt.Printf("💬 Service Details:\n")
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
				fmt.Printf("\n Database Credentials:\n")
				for key, value := range result.Credentials {
					fmt.Printf("   %s: %s\n", key, value)
				}
			}

			fmt.Printf("\n📝 Next Steps:\n")
			fmt.Printf("   1. Open Mattermost in your browser: http://localhost:%d\n", result.Port)
			fmt.Printf("   2. Create the first admin account\n")
			fmt.Printf("   3. Configure team settings and integrations\n")
			fmt.Printf("   4. Invite team members\n")
			fmt.Printf("   5. Check status: eos status mattermost\n")
		} else {
			logger.Error("Mattermost installation failed", zap.String("error", result.Error))
			fmt.Printf("\n❌ Mattermost Installation Failed!\n")
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
	CreateCmd.AddCommand(CreateMattermostCmd)

	CreateMattermostCmd.Flags().StringP("version", "v", "latest", "Mattermost version to install")
	CreateMattermostCmd.Flags().IntP("port", "p", 8065, "Port to expose Mattermost on")
	CreateMattermostCmd.Flags().BoolP("interactive", "i", false, "Interactive setup mode")
	CreateMattermostCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateMattermostCmd.Flags().String("work-dir", "", "Working directory for Mattermost installation")
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func runInteractiveMattermostSetup(options *service_installation.ServiceInstallOptions) error {
	fmt.Printf("Interactive Mattermost Setup\n")
	fmt.Printf("================================\n\n")

	// Version
	fmt.Printf("Mattermost version [%s]: ", options.Version)
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

	// Database password
	fmt.Print("Set custom database password? [y/N]: ")
	var setPassword string
	fmt.Scanln(&setPassword)
	if setPassword == "y" || setPassword == "Y" {
		fmt.Print("Database password: ")
		var password string
		fmt.Scanln(&password)
		if password != "" {
			options.Environment["DB_PASSWORD"] = password
		}
	}

	// Site URL
	fmt.Print("Set site URL (e.g., https://mattermost.example.com)? [y/N]: ")
	var setSiteURL string
	fmt.Scanln(&setSiteURL)
	if setSiteURL == "y" || setSiteURL == "Y" {
		fmt.Print("Site URL: ")
		var siteURL string
		fmt.Scanln(&siteURL)
		if siteURL != "" {
			options.Config["SITE_URL"] = siteURL
		}
	}

	fmt.Printf("\nConfiguration Summary:\n")
	fmt.Printf("   Version: %s\n", options.Version)
	fmt.Printf("   Port: %d\n", options.Port)
	if siteURL, exists := options.Config["SITE_URL"]; exists {
		fmt.Printf("   Site URL: %s\n", siteURL)
	}

	fmt.Print("\nProceed with installation? [Y/n]: ")
	var proceed string
	fmt.Scanln(&proceed)
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("installation cancelled by user")
	}

	return nil
}
