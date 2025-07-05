// cmd/create/caddy.go
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

// CreateCaddyCmd installs Caddy web server
var CreateCaddyCmd = &cobra.Command{
	Use:     "caddy",
	Short:   "Install Caddy web server",
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

			fmt.Printf("\n✅ Caddy Installation Complete!\n\n")
			fmt.Printf("🌐 Service Details:\n")
			fmt.Printf("   Version: %s\n", result.Version)
			fmt.Printf("   Method: %s (repository)\n", result.Method)
			fmt.Printf("   Duration: %s\n", result.Duration)

			if len(result.Endpoints) > 0 {
				fmt.Printf("\n🌐 Access URLs:\n")
				for _, endpoint := range result.Endpoints {
					fmt.Printf("   %s\n", endpoint)
				}
			}

			if len(result.ConfigFiles) > 0 {
				fmt.Printf("\n📁 Configuration Files:\n")
				for _, configFile := range result.ConfigFiles {
					fmt.Printf("   %s\n", configFile)
				}
			}

			fmt.Printf("\n📝 Next Steps:\n")
			fmt.Printf("   1. Edit the Caddyfile: sudo nano /etc/caddy/Caddyfile\n")
			fmt.Printf("   2. Add your site configuration\n")
			fmt.Printf("   3. Reload configuration: sudo systemctl reload caddy\n")
			fmt.Printf("   4. Check status: sudo systemctl status caddy\n")
			fmt.Printf("   5. View logs: sudo journalctl -u caddy -f\n")
			fmt.Printf("   6. Check service status: eos status caddy\n")
		} else {
			logger.Error("Caddy installation failed", zap.String("error", result.Error))
			fmt.Printf("\n❌ Caddy Installation Failed!\n")
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
	CreateCmd.AddCommand(CreateCaddyCmd)

	CreateCaddyCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive setup mode")
	CreateCaddyCmd.Flags().Bool("dry-run", false, "Simulate installation without making changes")
	CreateCaddyCmd.Flags().BoolP("force", "f", false, "Force installation even if conflicts exist")
	CreateCaddyCmd.Flags().Bool("skip-health-check", false, "Skip post-installation health check")
}

func runInteractiveCaddySetup(options *service_installation.ServiceInstallOptions) error {
	fmt.Printf("🔧 Interactive Caddy Setup\n")
	fmt.Printf("==========================\n\n")

	// Domain configuration
	fmt.Print("Primary domain for Caddy [example.com]: ")
	var domain string
	fmt.Scanln(&domain)
	if domain != "" {
		options.Domain = domain
		options.Config["primary_domain"] = domain
	}

	// Auto HTTPS
	fmt.Print("Enable automatic HTTPS? [Y/n]: ")
	var autoHTTPS string
	fmt.Scanln(&autoHTTPS)
	if autoHTTPS != "n" && autoHTTPS != "N" {
		options.Config["auto_https"] = "true"
	} else {
		options.Config["auto_https"] = "false"
	}

	// Port
	if domain == "" {
		fmt.Printf("HTTP port [%d]: ", options.Port)
		var portStr string
		fmt.Scanln(&portStr)
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
	fmt.Scanln(&adminAPI)
	if adminAPI == "y" || adminAPI == "Y" {
		options.Config["admin_api"] = "true"
		fmt.Print("Admin API port [2019]: ")
		var adminPortStr string
		fmt.Scanln(&adminPortStr)
		if adminPortStr != "" {
			options.Config["admin_port"] = adminPortStr
		} else {
			options.Config["admin_port"] = "2019"
		}
	}

	// File server
	fmt.Print("Set up as file server? [y/N]: ")
	var fileServer string
	fmt.Scanln(&fileServer)
	if fileServer == "y" || fileServer == "Y" {
		fmt.Print("Root directory [/var/www/html]: ")
		var rootDir string
		fmt.Scanln(&rootDir)
		if rootDir == "" {
			rootDir = "/var/www/html"
		}
		options.Config["file_server"] = "true"
		options.Config["root_dir"] = rootDir
	}

	fmt.Printf("\n📋 Configuration Summary:\n")
	fmt.Printf("   Domain: %s\n", options.Domain)
	fmt.Printf("   Auto HTTPS: %s\n", options.Config["auto_https"])
	fmt.Printf("   Port: %d\n", options.Port)
	fmt.Printf("   Admin API: %s\n", options.Config["admin_api"])
	if options.Config["file_server"] == "true" {
		fmt.Printf("   File Server: %s\n", options.Config["root_dir"])
	}

	fmt.Print("\nProceed with installation? [Y/n]: ")
	var proceed string
	fmt.Scanln(&proceed)
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("installation cancelled by user")
	}

	return nil
}