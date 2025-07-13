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

			logger.Info("terminal prompt: Mattermost Installation Complete!\n")
			logger.Info("terminal prompt: 💬 Service Details:")
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
				logger.Info("terminal prompt:  Database Credentials:")
				for key, value := range result.Credentials {
					logger.Info("terminal prompt:    %s: %s", key, value)
				}
			}

			logger.Info("terminal prompt: 📝 Next Steps:")
			logger.Info("terminal prompt:    1. Open Mattermost in your browser: http://localhost:%d", result.Port)
			logger.Info("terminal prompt:    2. Create the first admin account")
			logger.Info("terminal prompt:    3. Configure team settings and integrations")
			logger.Info("terminal prompt:    4. Invite team members")
			logger.Info("terminal prompt:    5. Check status: eos status mattermost")
		} else {
			logger.Error("Mattermost installation failed", zap.String("error", result.Error))
			logger.Info("terminal prompt: ❌ Mattermost Installation Failed!")
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
	CreateCmd.AddCommand(CreateMattermostCmd)

	CreateMattermostCmd.Flags().StringP("version", "v", "latest", "Mattermost version to install")
	CreateMattermostCmd.Flags().IntP("port", "p", 8065, "Port to expose Mattermost on")
	CreateMattermostCmd.Flags().BoolP("interactive", "i", false, "Interactive setup mode")
	CreateMattermostCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateMattermostCmd.Flags().String("work-dir", "", "Working directory for Mattermost installation")
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func runInteractiveMattermostSetup(options *service_installation.ServiceInstallOptions) error {
	logger.Info("terminal prompt: Interactive Mattermost Setup")
	logger.Info("terminal prompt: ================================\n")

	// Version
	logger.Info("terminal prompt: Mattermost version [%s]: ", options.Version)
	var version string
	fmt.Scanln(&version)
	if version != "" {
		options.Version = version
	}

	// Port
	logger.Info("terminal prompt: Port [%d]: ", options.Port)
	var portStr string
	fmt.Scanln(&portStr)
	if portStr != "" {
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
			options.Port = port
		}
	}

	// Database password
	logger.Info("terminal prompt: Set custom database password? [y/N]: ")
	var setPassword string
	fmt.Scanln(&setPassword)
	if setPassword == "y" || setPassword == "Y" {
		logger.Info("terminal prompt: Database password: ")
		var password string
		fmt.Scanln(&password)
		if password != "" {
			options.Environment["DB_PASSWORD"] = password
		}
	}

	// Site URL
	logger.Info("terminal prompt: Set site URL (e.g., https://mattermost.example.com)? [y/N]: ")
	var setSiteURL string
	fmt.Scanln(&setSiteURL)
	if setSiteURL == "y" || setSiteURL == "Y" {
		logger.Info("terminal prompt: Site URL: ")
		var siteURL string
		fmt.Scanln(&siteURL)
		if siteURL != "" {
			options.Config["SITE_URL"] = siteURL
		}
	}

	logger.Info("terminal prompt: Configuration Summary:")
	logger.Info("terminal prompt:    Version: %s", options.Version)
	logger.Info("terminal prompt:    Port: %d", options.Port)
	if siteURL, exists := options.Config["SITE_URL"]; exists {
		logger.Info("terminal prompt:    Site URL: %s", siteURL)
	}

	logger.Info("terminal prompt: \nProceed with installation? [Y/n]: ")
	var proceed string
	fmt.Scanln(&proceed)
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("installation cancelled by user")
	}

	return nil
}
