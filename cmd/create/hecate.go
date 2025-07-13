// cmd/hecate/create/create.gop

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/service_installation"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func init() {
	// Attach the hetzner-dns subcommand here
	CreateCmd.AddCommand(hetznerWildcardCmd)
	CreateCmd.AddCommand(CreateHecateCmd)
}

// CreateHecateCmd creates the `create hecate` subcommand
var CreateHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Fetch and set up Hecate reverse proxy framework",
	Long: `This command downloads the Hecate reverse proxy framework from its repository,
places it in /opt/hecate, and prepares it for use with Eos.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)
		log.Info(" Starting full Hecate setup wizard...")

		//  Call the full prompt + orchestrator flow
		if err := hecate.OrchestrateHecateWizard(rc); err != nil {
			log.Error(" Hecate setup failed", zap.Error(err))
			return err
		}

		log.Info(" Hecate setup completed successfully!")
		return nil
	}),
}

// CreateCaddyCmd installs Caddy web server
var CreateCaddyCmd = &cobra.Command{
	Use:   "caddy",
	Short: "Install Caddy web server",
	Long: `Install Caddy web server using the official repository.

Caddy is a modern, HTTP/2-enabled web server with automatic HTTPS that's easy 
to configure and use. This command installs Caddy from the official repository
and sets it up as a systemd service.

Examples:
  eos create caddy                     # Install with defaults
  eos create caddy --interactive       # Interactive setup
  eos create caddy --dry-run           # Test installation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		interactive, _ := cmd.Flags().GetBool("interactive")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		skipHealthCheck, _ := cmd.Flags().GetBool("skip-health-check")

		logger.Info("Installing Caddy",
			zap.Bool("interactive", interactive),
			zap.Bool("dry_run", dryRun))

		manager := service_installation.NewServiceInstallationManager()

		// Build installation options
		options := &service_installation.ServiceInstallOptions{
			Name:            "caddy",
			Type:            service_installation.ServiceTypeCaddy,
			Version:         "latest",
			Port:            80,
			Method:          service_installation.MethodRepository,
			Interactive:     interactive,
			DryRun:          dryRun,
			Force:           force,
			SkipHealthCheck: skipHealthCheck,
			Environment:     make(map[string]string),
			Config:          make(map[string]string),
		}

		// Interactive mode
		if interactive {
			if err := runInteractiveCaddySetup(options); err != nil {
				return fmt.Errorf("interactive setup failed: %w", err)
			}
		}

		// Perform installation
		result, err := manager.InstallService(rc, options)
		if err != nil {
			return fmt.Errorf("caddy installation failed: %w", err)
		}

		// Output result
		if result.Success {
			logger.Info("Caddy installation completed successfully",
				zap.String("version", result.Version),
				zap.Duration("duration", result.Duration))

			logger.Info("terminal prompt: Caddy Installation Complete!")
			logger.Info("terminal prompt: Service Details:",
				zap.String("version", result.Version),
				zap.String("method", result.Method+" (repository)"),
				zap.Duration("duration", result.Duration))

			if len(result.Endpoints) > 0 {
				logger.Info("terminal prompt: Access URLs:")
				for _, endpoint := range result.Endpoints {
					logger.Info("terminal prompt: "+endpoint)
				}
			}

			if len(result.ConfigFiles) > 0 {
				logger.Info("terminal prompt:  Configuration Files:")
				for _, configFile := range result.ConfigFiles {
					logger.Info(fmt.Sprintf("terminal prompt:    %s", configFile))
				}
			}

			logger.Info("terminal prompt: 📝 Next Steps:")
			logger.Info("terminal prompt:    1. Edit the Caddyfile: sudo nano /etc/caddy/Caddyfile")
			logger.Info("terminal prompt:    2. Add your site configuration")
			logger.Info("terminal prompt:    3. Reload configuration: sudo systemctl reload caddy")
			logger.Info("terminal prompt:    4. Check status: sudo systemctl status caddy")
			logger.Info("terminal prompt:    5. View logs: sudo journalctl -u caddy -f")
			logger.Info("terminal prompt:    6. Check service status: eos status caddy")
		} else {
			logger.Error("Caddy installation failed", zap.String("error", result.Error))
			logger.Info("terminal prompt: ❌ Caddy Installation Failed!")
			logger.Info(fmt.Sprintf("terminal prompt: Error: %s", result.Error))

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
					logger.Info(fmt.Sprintf("terminal prompt:    %s %s (%s)", status, step.Name, step.Duration))
					if step.Error != "" {
						logger.Info(fmt.Sprintf("terminal prompt:       Error: %s", step.Error))
					}
				}
			}
		}

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateCaddyCmd)

	CreateCaddyCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive setup mode")
	CreateCaddyCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateCaddyCmd.Flags().BoolP("force", "f", false, "Force installation even if conflicts exist")
	CreateCaddyCmd.Flags().Bool("skip-health-check", false, "Skip post-installation health check")
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func runInteractiveCaddySetup(options *service_installation.ServiceInstallOptions) error {
	fmt.Printf("\nInteractive Caddy Setup\n")
	fmt.Printf("==========================\n\n")

	// Domain configuration
	fmt.Print("Primary domain for Caddy [example.com]: ")
	var domain string
	if _, err := fmt.Scanln(&domain); err != nil {
		// If we can't read input, continue with empty domain
		fmt.Printf("Warning: Failed to read domain input: %v\n", err)
	}
	if domain != "" {
		options.Domain = domain
		options.Config["primary_domain"] = domain
	}

	// Auto HTTPS
	fmt.Print("Enable automatic HTTPS? [Y/n]: ")
	var autoHTTPS string
	if _, err := fmt.Scanln(&autoHTTPS); err != nil {
		// If we can't read input, default to enabled
		fmt.Printf("Warning: Failed to read HTTPS input, defaulting to enabled: %v\n", err)
		autoHTTPS = "Y"
	}
	if autoHTTPS != "n" && autoHTTPS != "N" {
		options.Config["auto_https"] = "true"
	} else {
		options.Config["auto_https"] = "false"
	}

	// Port
	if domain == "" {
		fmt.Printf("HTTP port [%d]: ", options.Port)
		var portStr string
		if _, err := fmt.Scanln(&portStr); err != nil {
			fmt.Printf("Warning: Failed to read port input, using default: %v\n", err)
		}
		if portStr != "" {
			var port int
			if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
				options.Port = port
			}
		}
	}

	// Admin API
	fmt.Print("Enable admin API? [y/N]: ")
	var adminAPI string
	if _, err := fmt.Scanln(&adminAPI); err != nil {
		fmt.Printf("Warning: Failed to read admin API input, defaulting to disabled: %v\n", err)
		adminAPI = "N"
	}
	if adminAPI == "y" || adminAPI == "Y" {
		options.Config["admin_api"] = "true"
		fmt.Print("Admin API port [2019]: ")
		var adminPortStr string
		if _, err := fmt.Scanln(&adminPortStr); err != nil {
			fmt.Printf("Warning: Failed to read admin port input, using default: %v\n", err)
		}
		if adminPortStr != "" {
			options.Config["admin_port"] = adminPortStr
		} else {
			options.Config["admin_port"] = "2019"
		}
	}

	// File server
	fmt.Print("Set up as file server? [y/N]: ")
	var fileServer string
	if _, err := fmt.Scanln(&fileServer); err != nil {
		fmt.Printf("Warning: Failed to read file server input, using default: %v\n", err)
	}
	if fileServer == "y" || fileServer == "Y" {
		fmt.Print("Root directory [/var/www/html]: ")
		var rootDir string
		if _, err := fmt.Scanln(&rootDir); err != nil {
			fmt.Printf("Warning: Failed to read root directory input, using default: %v\n", err)
		}
		if rootDir == "" {
			rootDir = "/var/www/html"
		}
		options.Config["file_server"] = "true"
		options.Config["root_dir"] = rootDir
	}

	fmt.Printf("\nConfiguration Summary:\n")
	fmt.Printf("   Domain: %s\n", options.Domain)
	fmt.Printf("   Auto HTTPS: %s\n", options.Config["auto_https"])
	fmt.Printf("   Port: %d\n", options.Port)
	fmt.Printf("   Admin API: %s\n", options.Config["admin_api"])
	if options.Config["file_server"] == "true" {
		fmt.Printf("   File Server: %s\n", options.Config["root_dir"])
	}

	fmt.Print("\nProceed with installation? [Y/n]: ")
	var proceed string
	if _, err := fmt.Scanln(&proceed); err != nil {
		fmt.Printf("Warning: Failed to read proceed input, using default: %v\n", err)
	}
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("installation cancelled by user")
	}

	return nil
}
