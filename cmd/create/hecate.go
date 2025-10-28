// cmd/hecate/create/create.gop

package create

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/services/service_installation"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func init() {
	// Attach the hetzner-dns subcommand here
	CreateCmd.AddCommand(hetznerWildcardCmd)
	CreateCmd.AddCommand(CreateHecateCmd)
}

var (
	configFile string
	outputDir  string
)

// CreateHecateCmd creates the `create hecate` subcommand
var CreateHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Deploy Hecate reverse proxy framework",
	Long: `Deploy Hecate reverse proxy framework using Docker Compose.

MODE 1: Interactive Wizard (Default - Human-Centric)
  Run without any flags to start an interactive wizard that guides you through:
  - Adding apps and their domains
  - Configuring backends (upstream services)
  - Optional SSO integration via Authentik
  - WebRTC/TCP port forwarding setup

  eos create hecate                                 # Interactive wizard (recommended)

MODE 2: YAML Configuration (For Automation)
  Deploy from a YAML config file that defines your apps and backends.
  Useful for scripted deployments or complex multi-service setups.

  Example config.yaml:
    apps:
      main:
        domain: cybermonkey.dev
        backend: 100.65.138.128:8009

      wazuh:
        domain: delphi.cybermonkey.dev
        backend: 100.88.163.85

      authentik:
        domain: hera.cybermonkey.dev

  eos create hecate --config config.yaml            # Deploy from YAML

The deployment creates configuration files at /opt/hecate/:
- docker-compose.yml - Container orchestration
- Caddyfile - Caddy reverse proxy configuration
- .env - Environment variables (includes Authentik bootstrap credentials)

Examples:
  eos create hecate                                 # Interactive wizard (starts automatically)
  eos create hecate --config example.yaml           # Deploy from YAML config
  eos create hecate --config example.yaml --output /opt/hecate  # Custom output dir
  eos create config --hecate                        # Generate YAML config only (no deployment)
  eos create hecate --help                          # Show this help message`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)
		log.Info("Starting Hecate deployment")

		// ASSESS - Check permissions for output directory
		if strings.HasPrefix(outputDir, "/opt/") || strings.HasPrefix(outputDir, "/etc/") {
			if os.Geteuid() != 0 {
				return eos_err.NewUserError(
					"Permission denied: %s requires root access\n\n"+
						"Run with sudo:\n"+
						"  sudo eos create hecate --config %s\n"+
						"  sudo eos create hecate\n\n"+
						"Or use a user-writable directory:\n"+
						"  eos create hecate --output ~/hecate",
					outputDir, configFile)
			}
		}

		// ASSESS - Discover environment for secret management
		log.Info("Discovering environment configuration")
		envConfig, err := environment.DiscoverEnvironment(rc)
		if err != nil {
			return fmt.Errorf("failed to discover environment: %w", err)
		}

		var config *hecate.YAMLHecateConfig
		var tempConfigPath string

		// Check if config file was provided (YAML override)
		if configFile != "" {
			log.Info("Using YAML configuration file",
				zap.String("config_file", configFile),
				zap.String("output_dir", outputDir))

			// Load YAML configuration
			config, err = hecate.LoadYAMLConfig(rc, configFile)
			if err != nil {
				return fmt.Errorf("failed to load YAML config: %w", err)
			}
		} else {
			// No YAML file provided - check if we can run interactive wizard
			log.Info("No config file provided, checking if interactive mode is available")

			// P0 FIX: Detect non-interactive environment (CI/CD, piped input, etc.)
			if !interaction.IsTTY() {
				log.Error("Cannot run interactive wizard in non-interactive environment")
				return eos_err.NewUserError(
					"No configuration file provided and running in non-interactive mode\n\n" +
						"Eos requires a configuration to deploy Hecate. You have two options:\n\n" +
						"OPTION 1: Provide a YAML configuration file\n" +
						"  eos create hecate --config hecate-config.yaml\n\n" +
						"OPTION 2: Generate configuration interactively (requires a TTY)\n" +
						"  Run from an interactive terminal:\n" +
						"  eos create hecate\n\n" +
						"For CI/CD pipelines, use OPTION 1 with a pre-generated config file.\n" +
						"To generate a config file without deploying:\n" +
						"  eos create config --hecate --output hecate-config.yaml")
			}

			// We have a TTY - run interactive wizard
			log.Info("Terminal detected, starting interactive wizard")

			// Generate temporary config file path
			tempConfigPath = "/tmp/hecate-config-wizard.yaml"
			defer func() {
				// P2 FIX: Only remove temp file on success, preserve for debugging on failure
				if tempConfigPath != "" && err == nil {
					_ = os.Remove(tempConfigPath)
				} else if tempConfigPath != "" && err != nil {
					log.Warn("Temp config file preserved for debugging",
						zap.String("path", tempConfigPath),
						zap.Error(err))
				}
			}()

			// Run interactive config generator (same as 'eos create config --hecate')
			log.Info("terminal prompt: ")
			log.Info("terminal prompt: No configuration file provided.")
			log.Info("terminal prompt: Starting interactive wizard to configure Hecate...")
			log.Info("terminal prompt: ")

			if err := hecate.GenerateConfigFile(rc, tempConfigPath, true); err != nil {
				return fmt.Errorf("interactive configuration failed: %w", err)
			}

			// Load the generated config
			config, err = hecate.LoadYAMLConfig(rc, tempConfigPath)
			if err != nil {
				return fmt.Errorf("failed to load generated config: %w", err)
			}

			// DEFERRED (2025-10-28): Consul KV storage deferred to April-May 2026
			// See ROADMAP.md "Hecate Consul KV + Vault Integration" section
			log.Info("terminal prompt: ")
			log.Info("terminal prompt: ✓ Configuration complete! Proceeding with deployment...")
			log.Info("terminal prompt: ")
		}

		// Display detected apps
		log.Info("Configuration loaded successfully")
		log.Info("terminal prompt: Detected apps:")
		for appName, app := range config.Apps {
			features := []string{}
			if len(app.TCPPorts) > 0 {
				features = append(features, "TCP")
			}
			if app.RequiresCoturn {
				features = append(features, "WebRTC")
			}
			if app.SSO {
				features = append(features, "SSO")
			}

			featureStr := ""
			if len(features) > 0 {
				featureStr = fmt.Sprintf(" (%s)", strings.Join(features, ", "))
			}

			log.Info(fmt.Sprintf("terminal prompt:   %s (%s)%s -> %s:%d",
				appName, app.Type, featureStr, app.Backend, app.BackendPort))
		}

		if config.HasAuthentik {
			log.Info("terminal prompt: Infrastructure:")
			log.Info("terminal prompt:   Authentik SSO at " + config.AuthentikDomain)
		}
		if config.NeedsCoturn {
			log.Info("terminal prompt:   Coturn TURN/STUN server (WebRTC)")
		}
		if config.NeedsNginx {
			log.Info("terminal prompt:   Nginx stream proxy (TCP/UDP)")
		}

		// Validate DNS records
		log.Info("terminal prompt: ")
		log.Info("terminal prompt: Validating DNS records...")
		dnsResults, err := hecate.ValidateDNSWithHetzner(rc, config)
		if err != nil {
			log.Warn("DNS validation failed, continuing anyway",
				zap.Error(err))
		} else {
			allValid := true
			for _, result := range dnsResults {
				log.Info(fmt.Sprintf("terminal prompt:   %s: %s",
					result.Domain, result.Message))
				if !result.IsValid {
					allValid = false
				}
			}

			if !allValid {
				log.Info("terminal prompt: ")
				log.Info("terminal prompt:   WARNING: Some DNS records are not configured correctly")
				log.Info("terminal prompt:    Caddy will not be able to issue TLS certificates until DNS is fixed")
				log.Info("terminal prompt:    You can continue deployment, but services may not be accessible")
				log.Info("terminal prompt: ")
			}
		}

		// Generate infrastructure with secrets
		log.Info("Generating infrastructure configuration")
		if err := hecate.GenerateFromYAML(rc, config, outputDir, envConfig); err != nil {
			return fmt.Errorf("failed to generate configuration: %w", err)
		}

		// CRITICAL: Validate generated files before declaring success
		log.Info("Validating generated configuration files")
		if err := hecate.ValidateGeneratedFiles(rc, outputDir); err != nil {
			return fmt.Errorf("validation failed: %w\n\nGenerated files have errors. This is a bug in Eos. Please report this issue with the validation output above", err)
		}

		log.Info("terminal prompt: ")
		log.Info("terminal prompt: ✓ Hecate infrastructure generated successfully!")
		log.Info("terminal prompt: ")
		log.Info("terminal prompt:   PREREQUISITES:")
		log.Info("terminal prompt:   • DNS records must point to this server:")

		// Deduplicate domains for display
		uniqueDomains := make(map[string]bool)
		for _, app := range config.Apps {
			uniqueDomains[app.Domain] = true
		}
		for domain := range uniqueDomains {
			log.Info(fmt.Sprintf("terminal prompt:     - %s (A record → your server IP)", domain))
		}

		log.Info("terminal prompt:   • Ports 80, 443 must be available (not in use)")
		if config.NeedsCoturn {
			log.Info("terminal prompt:   • Coturn ports: 3478, 5349, 49160-49200/udp must be available")
		}
		if config.NeedsNginx {
			log.Info("terminal prompt:   • TCP ports must be available for stream proxying")
		}
		log.Info("terminal prompt: ")
		log.Info("terminal prompt: Next steps:")
		log.Info("terminal prompt:   1. Review generated files in " + outputDir)
		stepNum := 2
		if config.HasAuthentik {
			log.Info("terminal prompt:   2. Check .env file for Authentik bootstrap credentials")
			stepNum = 3
		}
		log.Info(fmt.Sprintf("terminal prompt:   %d. Start services: cd %s && docker compose up -d", stepNum, outputDir))
		stepNum++
		log.Info(fmt.Sprintf("terminal prompt:   %d. Check status: docker compose ps", stepNum))
		stepNum++

		// Consul registration step (only if not disabled)
		disableConsul, _ := cmd.Flags().GetBool("disable-consul")
		if !disableConsul {
			log.Info(fmt.Sprintf("terminal prompt:   %d. Register with Consul: sudo eos read consul services-docker --compose-file %s/docker-compose.yml", stepNum, outputDir))
			stepNum++
		}

		log.Info(fmt.Sprintf("terminal prompt:   %d. View logs: docker compose logs -f", stepNum))

		return nil
	}),
}

func init() {
	// Add flags
	CreateHecateCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to YAML configuration file")
	CreateHecateCmd.Flags().StringVarP(&outputDir, "output", "o", "/opt/hecate", "Output directory for generated files")

	// Consul integration (enabled by default for seamless service discovery)
	CreateHecateCmd.Flags().Bool("disable-consul", false, "Skip Consul agent deployment (default: false, agent deploys automatically)")
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
		result, err := service_installation.InstallService(rc, options)
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
				zap.String("method", string(result.Method)+" (repository)"),
				zap.Duration("duration", result.Duration))

			if len(result.Endpoints) > 0 {
				logger.Info("terminal prompt: Access URLs:")
				for _, endpoint := range result.Endpoints {
					logger.Info("terminal prompt: " + endpoint)
				}
			}

			if len(result.ConfigFiles) > 0 {
				logger.Info("terminal prompt:  Configuration Files:")
				for _, configFile := range result.ConfigFiles {
					logger.Info(fmt.Sprintf("terminal prompt:    %s", configFile))
				}
			}

			logger.Info("terminal prompt:  Next Steps:")
			logger.Info("terminal prompt:    1. Edit the Caddyfile: sudo nano /etc/caddy/Caddyfile")
			logger.Info("terminal prompt:    2. Add your site configuration")
			logger.Info("terminal prompt:    3. Reload configuration: sudo systemctl reload caddy")
			logger.Info("terminal prompt:    4. Check status: sudo systemctl status caddy")
			logger.Info("terminal prompt:    5. View logs: sudo journalctl -u caddy -f")
			logger.Info("terminal prompt:    6. Check service status: eos status caddy")
		} else {
			logger.Error("Caddy installation failed", zap.String("error", result.Error))
			logger.Info("terminal prompt:  Caddy Installation Failed!")
			logger.Info(fmt.Sprintf("terminal prompt: Error: %s", result.Error))

			if len(result.Steps) > 0 {
				logger.Info("terminal prompt: Installation Steps:")
				for _, step := range result.Steps {
					status := ""
					switch step.Status {
					case "failed":
						status = ""
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
