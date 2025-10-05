// cmd/create/helen.go
//
// # Helen Integration Specifications
//
// Helen is a dual-mode website deployment platform within the Eos infrastructure
// compiler framework. It supports both static website hosting and full Ghost CMS
// deployments, all orchestrated through Nomad and exposed via the Hecate reverse proxy.
//
// # Helen Integration Specifications
//
// ## Architecture
//
// Helen follows the Eos dual-layer architecture:
//
// - **Infrastructure Layer ()**: Manages prerequisites like Docker, Nomad, Consul
// - **Application Layer (Nomad)**: Deploys Helen as containerized workload
//
// ## Deployment Modes
//
// ### 1. Static Mode (Default)
// - **Purpose**: Serve static HTML/CSS/JS files
// - **Container**: nginx:alpine with security hardening
// - **Use Cases**: Hugo sites, Jekyll builds, plain HTML
// - **Resource Usage**: Minimal (128MB RAM, 500MHz CPU)
//
// ### 2. Ghost Mode
// - **Purpose**: Full Ghost CMS deployment
// - **Container**: ghost:5-alpine or custom build
// - **Use Cases**: Dynamic blogs, content management
// - **Database**: MySQL or SQLite
// - **Resource Usage**: Higher (1GB+ RAM, 1000MHz+ CPU)
//
// ## Integration Features
//
// **Hecate Reverse Proxy Integration:**
// - Automatic SSL certificate management
// - Custom domain configuration
// - Load balancing and health checks
// - Security headers and rate limiting
//
// **Nomad Orchestration:**
// - Container lifecycle management
// - Resource allocation and scaling
// - Health monitoring and restart policies
// - Service discovery integration
//
// **Storage Management:**
// - Persistent volume mounting for content
// - Backup and restore capabilities
// - Content synchronization options
// - Database persistence for Ghost mode
//
// ## Implementation Status
//
// - ✅ Dual-mode deployment (static and Ghost) implemented
// - ✅ Hecate reverse proxy integration operational
// - ✅ Nomad orchestration with resource management active
// - ✅ Storage management and persistence implemented
// - ✅ SSL certificate management and custom domains operational
//
// For detailed Helen implementation, see:
// - pkg/helen/ - Helen deployment and configuration logic
// - pkg/hecate/ - Reverse proxy integration and SSL management
// - cmd/create/helen.go - CLI command implementation and user interface
package create

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/helen"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var helenCmd = &cobra.Command{
	Use:   "helen",
	Short: "Deploy Helen website platform with static or Ghost CMS options",
	Long: `Deploy Helen, your business website platform, supporting both static site 
hosting and Ghost CMS deployments behind the Hecate reverse proxy.

Helen provides two deployment modes:

STATIC MODE (default):
- Nginx-based static website hosting
- Serves files from local directories  
- Perfect for Hugo, Jekyll, or plain HTML sites
- Minimal resource usage

GHOST MODE:
- Full Ghost CMS deployment
- MySQL/SQLite database support
- Content management interface
- Dynamic blog/website functionality

Both modes include:
- Automatic Hecate reverse proxy integration
- Vault secret management
- Nomad orchestration with health checks
- Blue-green deployment capabilities
- Automatic SSL via Hecate

The deployment follows the assessment->intervention->evaluation pattern for each
step to ensure reliable deployment and easy troubleshooting.

Examples:
  # Deploy static site (default mode)
  eos create helen --domain helen.example.com

  # Deploy Ghost CMS
  eos create helen --mode ghost --domain helen.example.com

  # Deploy Ghost with MySQL database
  eos create helen --mode ghost --domain helen.example.com --database mysql

  # Deploy with staging environment
  eos create helen --mode ghost --domain staging.helen.example.com --environment staging

  # Deploy static site from specific directory
  eos create helen --html-path /var/www/helen --domain helen.example.com

  # Deploy Ghost with authentication enabled
  eos create helen --mode ghost --domain helen.example.com --enable-auth`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse deployment mode first
		mode, _ := cmd.Flags().GetString("mode")
		mode = strings.ToLower(mode)

		logger.Info("Starting Helen deployment",
			zap.String("command", "create helen"),
			zap.String("mode", mode),
			zap.String("component", rc.Component))

		// Route to appropriate implementation based on mode
		switch mode {
		case "static":
			return deployHelenStatic(rc, cmd)
		case "ghost":
			return deployHelenGhost(rc, cmd)
		default:
			return fmt.Errorf("invalid mode '%s': must be 'static' or 'ghost'", mode)
		}
	}),
}

// deployHelenStatic handles the existing static site deployment
func deployHelenStatic(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	// This preserves the existing static deployment logic

	// Parse command line flags using existing helen package
	config, err := helen.ParseHelenFlags(cmd)
	if err != nil {
		logger.Error("Failed to parse command flags", zap.Error(err))
		return fmt.Errorf("flag parsing failed: %w", err)
	}

	// Add domain for Hecate integration - prompt if missing
	domain, _ := cmd.Flags().GetString("domain")
	if domain == "" {
		logger.Info("terminal prompt: Please enter the domain name for static site deployment")
		domain, err = eos_io.PromptInput(rc, "Domain (e.g., www.example.com)", "")
		if err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
	}
	config.Domain = domain

	// Log configuration
	logger.Info("Helen static deployment configuration",
		zap.String("mode", "static"),
		zap.String("domain", domain),
		zap.Int("port", config.Port),
		zap.String("namespace", config.Namespace),
		zap.String("html_path", config.PublicHTMLPath),
		zap.String("vault_addr", config.VaultAddr),
		zap.String("nomad_addr", config.NomadAddr))

	// Execute deployment using existing helen.Create
	if err := helen.Create(rc, config); err != nil {
		logger.Error("Helen static deployment failed", zap.Error(err))
		return fmt.Errorf("helen static deployment failed: %w", err)
	}

	// Configure Hecate reverse proxy for static site
	if err := helen.ConfigureHecateStaticRoute(rc, config); err != nil {
		logger.Error("Failed to configure Hecate route", zap.Error(err))
		return fmt.Errorf("hecate configuration failed: %w", err)
	}

	// Display success information
	logger.Info("Helen static site deployment completed successfully",
		zap.String("url", fmt.Sprintf("https://%s", domain)),
		zap.String("local_url", fmt.Sprintf("http://localhost:%d", config.Port)),
		zap.String("namespace", config.Namespace))

	displayStaticDeploymentInfo(rc, config, domain)

	return nil
}

// deployHelenGhost handles the new Ghost CMS deployment
func deployHelenGhost(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	// Parse Ghost-specific configuration
	ghostConfig, err := helen.ParseGhostFlags(cmd)
	if err != nil {
		logger.Error("Failed to parse Ghost configuration", zap.Error(err))
		return fmt.Errorf("ghost configuration parsing failed: %w", err)
	}

	// Ensure domain is provided - prompt if missing
	if ghostConfig.Domain == "" {
		logger.Info("terminal prompt: Please enter the domain name for Ghost deployment")
		domain, err := eos_io.PromptInput(rc, "Domain (e.g., blog.example.com)", "")
		if err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		ghostConfig.Domain = domain
	}

	logger.Info("Helen Ghost CMS deployment configuration",
		zap.String("mode", "ghost"),
		zap.String("domain", ghostConfig.Domain),
		zap.String("environment", ghostConfig.Environment),
		zap.String("database", ghostConfig.Database),
		zap.String("git_repo", ghostConfig.GitRepo),
		zap.Bool("enable_auth", ghostConfig.EnableAuth))

	// DIAGNOSE - Check prerequisites
	logger.Info("Checking prerequisites for Ghost deployment")
	if err := helen.CheckGhostPrerequisites(rc, ghostConfig); err != nil {
		logger.Error("Prerequisites check failed", zap.Error(err))
		return fmt.Errorf("prerequisites not met: %w", err)
	}

	// ASSESS - Prepare deployment resources
	logger.Info("Preparing Ghost deployment resources")

	// Prepare git repository if specified
	if ghostConfig.GitRepo != "" {
		repoPath, err := helen.PrepareGitRepository(rc, ghostConfig)
		if err != nil {
			logger.Error("Failed to prepare git repository", zap.Error(err))
			return fmt.Errorf("git preparation failed: %w", err)
		}
		ghostConfig.RepoPath = repoPath
	}

	// Create Vault secrets for Ghost
	logger.Info("Creating Vault secrets for Ghost configuration")
	vaultPaths, err := helen.CreateGhostVaultSecrets(rc, ghostConfig)
	if err != nil {
		logger.Error("Failed to create Vault secrets", zap.Error(err))
		return fmt.Errorf("vault configuration failed: %w", err)
	}
	ghostConfig.VaultPaths = vaultPaths

	// INTERVENE - Deploy Ghost
	logger.Info("Deploying Ghost CMS")

	// Deploy using Nomad
	if err := helen.DeployGhost(rc, ghostConfig); err != nil {
		logger.Error("Ghost deployment failed", zap.Error(err))
		return fmt.Errorf("ghost deployment failed: %w", err)
	}

	// Configure Hecate reverse proxy for Ghost
	if err := helen.ConfigureHecateGhostRoute(rc, ghostConfig); err != nil {
		logger.Error("Failed to configure Hecate route for Ghost", zap.Error(err))
		return fmt.Errorf("hecate configuration failed: %w", err)
	}

	// Set up CI/CD webhook if enabled
	if ghostConfig.EnableWebhook {
		webhookURL, err := helen.SetupGhostWebhook(rc, ghostConfig)
		if err != nil {
			logger.Warn("Failed to setup webhook", zap.Error(err))
		} else {
			logger.Info("CI/CD webhook configured", zap.String("url", webhookURL))
		}
	}

	// REVIEW - Verify deployment
	logger.Info("Verifying Ghost deployment")
	if err := helen.WaitForGhostHealthy(rc, ghostConfig); err != nil {
		logger.Error("Ghost health check failed", zap.Error(err))
		return fmt.Errorf("deployment verification failed: %w", err)
	}

	// Display success information
	logger.Info("Helen Ghost CMS deployment completed successfully",
		zap.String("url", fmt.Sprintf("https://%s", ghostConfig.Domain)),
		zap.String("admin_url", fmt.Sprintf("https://%s/ghost", ghostConfig.Domain)),
		zap.String("environment", ghostConfig.Environment))

	displayGhostDeploymentInfo(rc, ghostConfig)

	return nil
}

func displayStaticDeploymentInfo(rc *eos_io.RuntimeContext, config *helen.Config, domain string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Helen Static Site Deployment Complete!")
	logger.Info("terminal prompt: ========================================")
	logger.Info(fmt.Sprintf("terminal prompt: Website URL: https://%s", domain))
	logger.Info(fmt.Sprintf("terminal prompt: Local Access: http://localhost:%d", config.Port))
	logger.Info(fmt.Sprintf("terminal prompt: Serving From: %s", config.PublicHTMLPath))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Management Commands:")
	logger.Info(fmt.Sprintf("terminal prompt:   Status: eos read helen --namespace %s", config.Namespace))
	logger.Info(fmt.Sprintf("terminal prompt:   Update: eos update helen --namespace %s", config.Namespace))
	logger.Info(fmt.Sprintf("terminal prompt:   Logs: nomad alloc logs -job helen-%s", config.Namespace))
}

func displayGhostDeploymentInfo(rc *eos_io.RuntimeContext, config *helen.GhostConfig) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Helen Ghost CMS Deployment Complete!")
	logger.Info("terminal prompt: ======================================")
	logger.Info(fmt.Sprintf("terminal prompt: Website: https://%s", config.Domain))
	logger.Info(fmt.Sprintf("terminal prompt: Admin Panel: https://%s/ghost", config.Domain))
	logger.Info(fmt.Sprintf("terminal prompt: Environment: %s", config.Environment))
	logger.Info(fmt.Sprintf("terminal prompt: Database: %s", config.Database))
	if config.EnableAuth {
		logger.Info("terminal prompt: Authentication: Enabled via Authentik")
	}
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: First-Time Setup:")
	logger.Info("terminal prompt:   1. Visit the admin panel URL above")
	logger.Info("terminal prompt:   2. Complete the Ghost setup wizard")
	logger.Info("terminal prompt:   3. Configure email settings in Ghost admin")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Management Commands:")
	logger.Info(fmt.Sprintf("terminal prompt:   Status: eos read helen --mode ghost --environment %s", config.Environment))
	logger.Info(fmt.Sprintf("terminal prompt:   Update: eos update helen --mode ghost --environment %s", config.Environment))
	logger.Info(fmt.Sprintf("terminal prompt:   Backup: eos backup helen --environment %s", config.Environment))
	logger.Info(fmt.Sprintf("terminal prompt:   Logs: nomad alloc logs -job helen-ghost-%s", config.Environment))
}

func init() {
	// Add helen command to create
	CreateCmd.AddCommand(helenCmd)

	// Deployment mode selection
	helenCmd.Flags().String("mode", "static", "Deployment mode: 'static' or 'ghost'")

	// Common flags for both modes
	helenCmd.Flags().String("domain", "", "Domain name for the website (required)")
	helenCmd.Flags().String("namespace", "helen", "Nomad namespace for deployment")
	helenCmd.Flags().String("vault-addr", "http://localhost:8179", "Vault server address")
	helenCmd.Flags().String("nomad-addr", "http://localhost:4646", "Nomad server address")
	helenCmd.Flags().String("work-dir", "/tmp/helen-deploy", "Working directory for deployment files")
	helenCmd.Flags().IntP("port", "p", shared.PortHelen, "Port to expose Helen on")

	// Static mode specific flags (existing)
	helenCmd.Flags().String("html-path", "./public", "Path to HTML files to serve (static mode)")
	helenCmd.Flags().String("host", "0.0.0.0", "Host to bind services to")
	helenCmd.Flags().Int("cpu", 500, "CPU allocation in MHz")
	helenCmd.Flags().Int("memory", 128, "Memory allocation in MB")

	// Ghost mode specific flags (new)
	helenCmd.Flags().String("environment", "production", "Deployment environment (dev/staging/production)")
	helenCmd.Flags().String("git-repo", "", "Git repository URL for Helen Ghost configuration")
	helenCmd.Flags().String("git-branch", "main", "Git branch to deploy")
	helenCmd.Flags().Bool("enable-auth", false, "Enable Authentik authentication")
	helenCmd.Flags().String("database", "mysql", "Database type: 'mysql' or 'sqlite'")
	helenCmd.Flags().Bool("enable-webhook", false, "Enable CI/CD webhook for auto-deployment")
	helenCmd.Flags().Int("ghost-instances", 1, "Number of Ghost instances to deploy")

	// Mark domain as required
	// Remove MarkFlagRequired for domain - will prompt interactively if not provided
	// helenCmd.MarkFlagRequired("domain")

	// Update examples
	helenCmd.Example = `  # Deploy static site (default)
  eos create helen --domain helen.example.com

  # Deploy static site with custom directory
  eos create helen --domain helen.example.com --html-path /var/www/helen

  # Deploy Ghost CMS
  eos create helen --mode ghost --domain helen.example.com

  # Deploy Ghost with MySQL and authentication
  eos create helen --mode ghost --domain helen.example.com --database mysql --enable-auth

  # Deploy Ghost to staging environment
  eos create helen --mode ghost --domain staging.helen.example.com --environment staging

  # Deploy Ghost with CI/CD webhook
  eos create helen --mode ghost --domain helen.example.com --enable-webhook`
}
