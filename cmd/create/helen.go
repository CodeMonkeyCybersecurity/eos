package create

import (
	"fmt"

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
	Short: "Deploy Helen nginx static website with secure Nomad and Vault integration",
	Long: `Deploy Helen, a secure nginx-based static website platform, using HashiCorp's 
stack for reliable, scalable deployment on localhost.

Helen provides:
- Secure nginx container with read-only filesystem
- Static website hosting from local directories
- Security hardening with tmpfs mounts
- Non-root user execution
- Comprehensive health checks

This deployment includes:
- Nginx:alpine container serving static files
- Vault integration for deployment metadata
- Nomad orchestration with health checks
- Security best practices implementation

The deployment follows the assessment->intervention->evaluation pattern for each
step to ensure reliable deployment and easy troubleshooting.

Examples:
  # Deploy with default settings (port 8009, ./public directory)
  eos create helen

  # Deploy with custom HTML directory
  eos create helen --html-path /var/www/html

  # Deploy to specific namespace
  eos create helen --namespace production

  # Deploy with custom Vault/Nomad addresses
  eos create helen --vault-addr http://localhost:8179 --nomad-addr http://localhost:4646

  # Deploy with custom resource limits
  eos create helen --cpu 1000 --memory 256`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Starting Helen nginx deployment",
			zap.String("command", "create helen"),
			zap.String("component", rc.Component))

		// Parse command line flags
		config, err := helen.ParseHelenFlags(cmd)
		if err != nil {
			logger.Error("Failed to parse command flags", zap.Error(err))
			return fmt.Errorf("flag parsing failed: %w", err)
		}

		// Log configuration
		logger.Info("Helen deployment configuration",
			zap.Int("port", config.Port),
			zap.String("namespace", config.Namespace),
			zap.String("html_path", config.PublicHTMLPath),
			zap.String("vault_addr", config.VaultAddr),
			zap.String("nomad_addr", config.NomadAddr),
			zap.String("work_dir", config.WorkDir))

		// Execute deployment
		if err := helen.Create(rc, config); err != nil {
			logger.Error("Helen deployment failed", zap.Error(err))
			return fmt.Errorf("helen deployment failed: %w", err)
		}

		// Display success information
		logger.Info("Helen deployment completed successfully",
			zap.String("url", fmt.Sprintf("http://localhost:%d", config.Port)),
			zap.String("namespace", config.Namespace))

		logger.Info("Access Helen",
			zap.String("web_interface", fmt.Sprintf("http://localhost:%d", config.Port)),
			zap.String("serving_from", config.PublicHTMLPath))

		logger.Info("Next steps",
			zap.String("status_check", fmt.Sprintf("eos read helen --namespace %s", config.Namespace)),
			zap.String("health_check", fmt.Sprintf("eos status helen --namespace %s", config.Namespace)),
			zap.String("logs", "nomad alloc logs <alloc-id>"))

		return nil
	}),
}

func init() {
	// Add helen command to create
	CreateCmd.AddCommand(helenCmd)

	// Basic configuration flags
	helenCmd.Flags().IntP("port", "p", shared.PortHelen, "Port to expose Helen on")
	helenCmd.Flags().String("namespace", "helen", "Nomad namespace for deployment")
	helenCmd.Flags().String("vault-addr", "http://localhost:8179", "Vault server address")
	helenCmd.Flags().String("nomad-addr", "http://localhost:4646", "Nomad server address")
	helenCmd.Flags().String("work-dir", "/tmp/helen-deploy", "Working directory for deployment files")
	helenCmd.Flags().String("host", "0.0.0.0", "Host to bind services to")
	helenCmd.Flags().String("html-path", "./public", "Path to HTML files to serve")
	helenCmd.Flags().String("project-name", "helen", "Project name for the deployment")

	// Resource configuration flags
	helenCmd.Flags().Int("cpu", 500, "CPU allocation in MHz for nginx")
	helenCmd.Flags().Int("memory", 128, "Memory allocation in MB for nginx")

	// Set flag usage examples
	helenCmd.Example = `  # Deploy Helen with default settings
  eos create helen

  # Deploy with custom HTML directory
  eos create helen --html-path /var/www/html

  # Deploy on custom port with specific namespace
  eos create helen --port 8080 --namespace production

  # Deploy with high-performance settings
  eos create helen --cpu 1000 --memory 256

  # Deploy with custom project name
  eos create helen --project-name my-website`
}
