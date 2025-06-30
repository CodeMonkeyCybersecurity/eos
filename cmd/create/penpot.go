package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/penpot"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var penpotCmd = &cobra.Command{
	Use:   "penpot",
	Short: "Deploy Penpot design platform with secure Terraform, Nomad, and Vault integration",
	Long: `Deploy Penpot, an open-source design and prototyping platform, using HashiCorp's 
enterprise stack for secure, scalable deployment.

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
  eos create penpot --vault-addr https://vault.example.com:8200 --nomad-addr https://nomad.example.com:4646

  # Deploy with disabled registration
  eos create penpot --disable-registration

  # Deploy with custom resource limits
  eos create penpot --backend-cpu 2000 --backend-memory 4096`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		logger.Info("🎨 Starting Penpot deployment",
			zap.String("command", "create penpot"),
			zap.String("component", rc.Component))
		
		// Parse command line flags
		config, err := parsePenpotFlags(cmd)
		if err != nil {
			logger.Error("❌ Failed to parse command flags", zap.Error(err))
			return fmt.Errorf("flag parsing failed: %w", err)
		}
		
		// Log configuration
		logger.Info("📋 Penpot deployment configuration",
			zap.Int("port", config.Port),
			zap.String("namespace", config.Namespace),
			zap.String("vault_addr", config.VaultAddr),
			zap.String("nomad_addr", config.NomadAddr),
			zap.Bool("enable_registration", config.EnableRegistration),
			zap.String("work_dir", config.WorkDir))
		
		// Execute deployment
		if err := penpot.Create(rc, config); err != nil {
			logger.Error("❌ Penpot deployment failed", zap.Error(err))
			return fmt.Errorf("penpot deployment failed: %w", err)
		}
		
		// Display success information
		logger.Info("🎉 Penpot deployment completed successfully",
			zap.String("url", fmt.Sprintf("http://localhost:%d", config.Port)),
			zap.String("namespace", config.Namespace))
		
		logger.Info("🌐 Access Penpot",
			zap.String("web_interface", fmt.Sprintf("http://localhost:%d", config.Port)),
			zap.String("default_credentials", "Create account via registration form"))
		
		logger.Info("📚 Next steps",
			zap.String("status_check", fmt.Sprintf("eos read penpot --namespace %s", config.Namespace)),
			zap.String("health_check", fmt.Sprintf("eos status penpot --namespace %s", config.Namespace)),
			zap.String("logs", "nomad alloc logs <alloc-id>"))
		
		return nil
	}),
}

// parsePenpotFlags parses command line flags and returns a Penpot configuration
func parsePenpotFlags(cmd *cobra.Command) (*penpot.Config, error) {
	// Start with default configuration
	config := penpot.DefaultConfig()
	
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
	config.PublicURI = fmt.Sprintf("http://localhost:%d", config.Port)
	
	return config, nil
}

func init() {
	// Add penpot command to create
	CreateCmd.AddCommand(penpotCmd)
	
	// Basic configuration flags
	penpotCmd.Flags().IntP("port", "p", shared.PortPenpot, "Port to expose Penpot on")
	penpotCmd.Flags().String("namespace", "penpot", "Nomad namespace for deployment")
	penpotCmd.Flags().String("vault-addr", "http://localhost:8200", "Vault server address")
	penpotCmd.Flags().String("nomad-addr", "http://localhost:4646", "Nomad server address")
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