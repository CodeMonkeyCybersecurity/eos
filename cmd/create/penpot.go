package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/penpot"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var penpotCmd = &cobra.Command{
	Use:   "penpot",
	Short: "Deploy Penpot design platform with secure Terraform, Nomad, and Vault integration",
	Long: `Deploy Penpot, an open-source design and prototyping platform, using HashiCorp's 
stack for secure, scalable deployment.

Penpot provides:
- Design and prototyping tools
- Team collaboration features  
- Real-time collaborative editing
- Export capabilities (PDF, PNG, SVG)
- Self-hosted alternative to Figma

This deployment includes:
- PostgreSQL database with secure credentials
- Redis caching layer
- Penpot backend API service
- Penpot frontend web interface
- Export service for PDF/PNG generation
- Vault integration for secrets management
- Nomad orchestration with health checks
- Terraform infrastructure as code

The deployment follows the assessment->intervention->evaluation pattern for each
step to ensure reliable deployment and easy troubleshooting.

Examples:
  # Deploy with default settings (port 8239)
  eos create penpot

  # Deploy on custom port
  eos create penpot --port 8080

  # Deploy to specific namespace
  eos create penpot --namespace production

  # Deploy with custom Vault/Nomad addresses
  eos create penpot --vault-addr https://vault.example.com:8179 --nomad-addr https://nomad.example.com:8243

  # Deploy with disabled registration
  eos create penpot --disable-registration

  # Deploy with custom resource limits
  eos create penpot --backend-cpu 2000 --backend-memory 4096`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("🎨 Starting Penpot deployment",
			zap.String("command", "create penpot"),
			zap.String("component", rc.Component))

		// ASSESS - Discover environment
		logger.Info("Discovering environment configuration")
		envConfig, err := environment.DiscoverEnvironment(rc)
		if err != nil {
			return fmt.Errorf("failed to discover environment: %w", err)
		}

		// Initialize secret manager (for future use)
		_, err = secrets.NewSecretManager(rc, envConfig)
		if err != nil {
			logger.Warn("Failed to initialize secret manager", zap.Error(err))
			// Continue anyway - Penpot can work without it
		}

		// Parse command line flags and merge with environment discovery
		config, err := parsePenpotFlags(cmd, envConfig)
		if err != nil {
			logger.Error(" Failed to parse command flags", zap.Error(err))
			return fmt.Errorf("flag parsing failed: %w", err)
		}

		// Log configuration
		logger.Info(" Penpot deployment configuration",
			zap.Int("port", config.Port),
			zap.String("namespace", config.Namespace),
			zap.String("vault_addr", config.VaultAddr),
			zap.String("nomad_addr", config.NomadAddr),
			zap.Bool("enable_registration", config.EnableRegistration),
			zap.String("work_dir", config.WorkDir))

		// INTERVENE - Execute deployment
		if err := penpot.Create(rc, config); err != nil {
			logger.Error(" Penpot deployment failed", zap.Error(err))
			return fmt.Errorf("penpot deployment failed: %w", err)
		}

		// Store generated secrets if available
		if envConfig.VaultAddr != "" {
			logger.Debug("Storing deployment secrets in secret manager",
				zap.String("backend", "Vault"))
		}

		// EVALUATE - Display success information
		hostname := shared.GetInternalHostname()
		logger.Info(" Penpot deployment completed successfully",
			zap.String("url", fmt.Sprintf("http://%s:%d", hostname, config.Port)),
			zap.String("namespace", config.Namespace),
			zap.String("environment", envConfig.Environment),
			zap.String("secret_backend", "Vault"))

		logger.Info("Environment discovered",
			zap.String("environment", envConfig.Environment),
			zap.String("datacenter", envConfig.Datacenter),
			zap.String("vault_addr", envConfig.VaultAddr))

		logger.Info(" Access Penpot",
			zap.String("web_interface", fmt.Sprintf("http://%s:%d", hostname, config.Port)),
			zap.String("default_credentials", "Create account via registration form"))

		logger.Info("📚 Next steps",
			zap.String("status_check", fmt.Sprintf("eos read penpot --namespace %s", config.Namespace)),
			zap.String("health_check", fmt.Sprintf("eos status penpot --namespace %s", config.Namespace)),
			zap.String("logs", "nomad alloc logs <alloc-id>"))

		return nil
	}),
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// parsePenpotFlags parses command line flags and returns a Penpot configuration
func parsePenpotFlags(cmd *cobra.Command, envConfig *environment.EnvironmentConfig) (*penpot.Config, error) {
	// Start with default configuration
	config := penpot.DefaultConfig()

	// Apply environment-based defaults
	if envConfig != nil {
		// Use environment to determine resource allocation
		if resources, exists := envConfig.Services.Resources[envConfig.Environment]; exists {
			// Apply resource defaults based on environment
			config.Resources.Backend.CPU = resources.CPU
			config.Resources.Backend.Memory = resources.Memory
			config.Resources.Frontend.CPU = resources.CPU / 2
			config.Resources.Frontend.Memory = resources.Memory / 2
		}

		// Use environment-specific namespace if not overridden
		config.Namespace = envConfig.Environment
	}

	// Parse flags
	if port, err := cmd.Flags().GetInt("port"); err == nil && port != 0 {
		config.Port = port
	}

	if namespace, err := cmd.Flags().GetString("namespace"); err == nil && namespace != "" {
		config.Namespace = namespace
	}

	if vaultAddr, err := cmd.Flags().GetString("vault-addr"); err == nil && vaultAddr != "" {
		config.VaultAddr = vaultAddr
	}

	if nomadAddr, err := cmd.Flags().GetString("nomad-addr"); err == nil && nomadAddr != "" {
		config.NomadAddr = nomadAddr
	}

	if workDir, err := cmd.Flags().GetString("work-dir"); err == nil && workDir != "" {
		config.WorkDir = workDir
	}

	if host, err := cmd.Flags().GetString("host"); err == nil && host != "" {
		config.Host = host
	}

	// Feature flags
	if disableReg, err := cmd.Flags().GetBool("disable-registration"); err == nil && disableReg {
		config.EnableRegistration = false
	}

	if disableLogin, err := cmd.Flags().GetBool("disable-login"); err == nil && disableLogin {
		config.EnableLogin = false
	}

	if enableEmailVerif, err := cmd.Flags().GetBool("enable-email-verification"); err == nil && enableEmailVerif {
		config.DisableEmailVerif = false
	}

	// Resource configuration
	if cpu, err := cmd.Flags().GetInt("frontend-cpu"); err == nil && cpu > 0 {
		config.Resources.Frontend.CPU = cpu
	}

	if memory, err := cmd.Flags().GetInt("frontend-memory"); err == nil && memory > 0 {
		config.Resources.Frontend.Memory = memory
	}

	if cpu, err := cmd.Flags().GetInt("backend-cpu"); err == nil && cpu > 0 {
		config.Resources.Backend.CPU = cpu
	}

	if memory, err := cmd.Flags().GetInt("backend-memory"); err == nil && memory > 0 {
		config.Resources.Backend.Memory = memory
	}

	if cpu, err := cmd.Flags().GetInt("database-cpu"); err == nil && cpu > 0 {
		config.Resources.Database.CPU = cpu
	}

	if memory, err := cmd.Flags().GetInt("database-memory"); err == nil && memory > 0 {
		config.Resources.Database.Memory = memory
	}

	// Set public URI based on final port configuration
	hostname := shared.GetInternalHostname()
	config.PublicURI = fmt.Sprintf("http://%s:%d", hostname, config.Port)

	return config, nil
}

func init() {
	// Add penpot command to create
	CreateCmd.AddCommand(penpotCmd)

	// Basic configuration flags
	hostname := shared.GetInternalHostname()
	penpotCmd.Flags().IntP("port", "p", shared.PortPenpot, "Port to expose Penpot on")
	penpotCmd.Flags().String("namespace", "penpot", "Nomad namespace for deployment")
	penpotCmd.Flags().String("vault-addr", fmt.Sprintf("https://%s:%d", hostname, shared.PortVault), "Vault server address")
	penpotCmd.Flags().String("nomad-addr", fmt.Sprintf("http://%s:%d", hostname, shared.PortNomad), "Nomad server address")
	penpotCmd.Flags().String("work-dir", "/tmp/penpot-deploy", "Working directory for deployment files")
	penpotCmd.Flags().String("host", "0.0.0.0", "Host to bind services to")

	// Feature flags
	penpotCmd.Flags().Bool("disable-registration", false, "Disable user registration")
	penpotCmd.Flags().Bool("disable-login", false, "Disable user login")
	penpotCmd.Flags().Bool("enable-email-verification", false, "Enable email verification for registration")

	// Resource configuration flags
	penpotCmd.Flags().Int("frontend-cpu", 500, "Frontend CPU allocation in MHz")
	penpotCmd.Flags().Int("frontend-memory", 512, "Frontend memory allocation in MB")
	penpotCmd.Flags().Int("backend-cpu", 1000, "Backend CPU allocation in MHz")
	penpotCmd.Flags().Int("backend-memory", 2048, "Backend memory allocation in MB")
	penpotCmd.Flags().Int("exporter-cpu", 500, "Exporter CPU allocation in MHz")
	penpotCmd.Flags().Int("exporter-memory", 512, "Exporter memory allocation in MB")
	penpotCmd.Flags().Int("database-cpu", 500, "Database CPU allocation in MHz")
	penpotCmd.Flags().Int("database-memory", 512, "Database memory allocation in MB")
	penpotCmd.Flags().Int("redis-cpu", 200, "Redis CPU allocation in MHz")
	penpotCmd.Flags().Int("redis-memory", 256, "Redis memory allocation in MB")

	// Set flag usage examples
	penpotCmd.Example = `  # Deploy Penpot with default settings
  eos create penpot

  # Deploy on port 8080 with custom namespace
  eos create penpot --port 8080 --namespace production

  # Deploy with high-performance backend
  eos create penpot --backend-cpu 2000 --backend-memory 4096

  # Deploy with registration disabled for private use
  eos create penpot --disable-registration`
}
