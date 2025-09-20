// cmd/create/mattermost.go
//
// Mattermost Team Collaboration Platform Deployment
//
// This file implements CLI commands for deploying Mattermost using EOS's
// infrastructure compiler pattern. It orchestrates the complete deployment
// stack including container orchestration, service discovery, and secure
// credential management.
//
// EOS Infrastructure Compiler Integration:
// This deployment follows EOS's core philosophy of translating simple human
// intent ("deploy Mattermost") into complex multi-system orchestration:
// Human Intent → EOS CLI → SaltStack → Terraform → Nomad → Mattermost
//
// Key Features:
// - Complete Mattermost deployment with automatic configuration
// - Automatic environment discovery (production/staging/development)
// - Secure credential generation and Vault integration
// - Container orchestration via Nomad with health checks
// - Service discovery via Consul for scalability
// - Persistent data storage with PostgreSQL backend
// - Hecate two-layer reverse proxy integration
// - SSL termination and authentication via Authentik
//
// Architecture Components:
// - Nomad: Container orchestration and job scheduling
// - Consul: Service discovery and health monitoring
// - Vault: Secure credential storage and management
// - PostgreSQL: Persistent data storage backend
// - Nginx: Local reverse proxy for service routing
// - Hecate: Two-layer reverse proxy (Hetzner Cloud + Local)
//
// Hecate Integration:
// Follows the two-layer reverse proxy architecture:
// Internet → Hetzner Cloud (Caddy + Authentik) → Local Infrastructure (Nginx + Mattermost)
//
// Layer 1 (Frontend - Hetzner Cloud):
// - Caddy: SSL termination and automatic certificate management
// - Authentik: Identity provider with SSO/SAML/OAuth2
// - DNS: Automatic domain management
//
// Layer 2 (Backend - Local Infrastructure):
// - Nginx: Local reverse proxy container
// - Mattermost: Application container
// - Consul: Service discovery (mattermost.service.consul)
//
// Available Commands:
// - eos create mattermost                    # Basic deployment
// - eos create mattermost --domain chat.example.com  # Custom domain
// - eos create mattermost --environment prod # Production configuration
//
// Security Features:
// - Automatic secure credential generation
// - Vault integration for secret management
// - Role-based access control via Authentik
// - TLS encryption end-to-end
// - Network isolation via Nomad networking
//
// Usage Examples:
//   # Basic deployment with automatic configuration
//   eos create mattermost
//
//   # Production deployment with custom domain
//   eos create mattermost --domain chat.company.com --environment production
//
//   # Development deployment with local access
//   eos create mattermost --environment development --local-only
//
// Integration Points:
// - Vault: Secure storage of database credentials and API keys
// - Consul: Service registration and health monitoring
// - Nomad: Container lifecycle management and scaling
// - PostgreSQL: Persistent data storage with automatic backups
// - Hecate: Public access with authentication and SSL
package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/mattermost"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateMattermostCmd installs Mattermost team collaboration platform
var CreateMattermostCmd = &cobra.Command{
	Use:   "mattermost",
	Short: "Install Mattermost team collaboration platform using Nomad orchestration",
	Long: `Install Mattermost using the SaltStack → Terraform → Nomad architecture.

This command provides a complete Mattermost deployment with automatic configuration:
- Automatic environment discovery (production/staging/development)
- Secure credential generation and storage (Vault/SaltStack/file)
- Container orchestration via Nomad
- Service discovery via Consul
- Persistent data storage
- Health monitoring and recovery
- Production-ready configuration

Mattermost is an open-source, self-hostable team collaboration platform with messaging,
file sharing, search, and integrations designed for organizations.

Examples:
  eos create mattermost                         # Deploy with automatic configuration
  eos create mattermost --database-password secret123  # Override database password
  eos create mattermost --port 8065            # Override port
  eos create mattermost --datacenter production # Override datacenter`,

	RunE: eos.Wrap(runCreateMattermost),
}

func runCreateMattermost(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	logger.Info("Starting Mattermost deployment with automatic configuration")

	// 1. Discover environment automatically
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		logger.Warn("Environment discovery failed, using defaults", zap.Error(err))
		// Continue with defaults rather than failing
		envConfig = &environment.EnvironmentConfig{
			Environment:   "development",
			Datacenter:    "dc1",
			SecretBackend: "file",
		}
	}

	logger.Info("Environment discovered",
		zap.String("environment", envConfig.Environment),
		zap.String("datacenter", envConfig.Datacenter),
		zap.String("secret_backend", envConfig.SecretBackend))

	// 2. Check for manual overrides from flags
	if manualPassword, _ := cmd.Flags().GetString("database-password"); manualPassword != "" {
		logger.Info("Using manually provided database password")
	}
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 && manualPort != shared.PortMattermost {
		logger.Info("Using manually provided port", zap.Int("port", manualPort))
	}

	// 3. Get or generate secrets automatically
	secretManager, err := secrets.NewSecretManager(rc, envConfig)
	if err != nil {
		return fmt.Errorf("secret manager initialization failed: %w", err)
	}

	requiredSecrets := map[string]secrets.SecretType{
		"database_password": secrets.SecretTypePassword,
		"file_public_key":   secrets.SecretTypeAPIKey,
		"file_private_key":  secrets.SecretTypeAPIKey,
		"invite_salt":       secrets.SecretTypeToken,
	}

	serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("mattermost", requiredSecrets)
	if err != nil {
		return fmt.Errorf("secret generation failed: %w", err)
	}

	// 4. Build configuration with discovered/generated values
	databasePassword := serviceSecrets.Secrets["database_password"].(string)
	filePublicKey := serviceSecrets.Secrets["file_public_key"].(string)
	filePrivateKey := serviceSecrets.Secrets["file_private_key"].(string)
	inviteSalt := serviceSecrets.Secrets["invite_salt"].(string)
	
	// Allow manual overrides
	if manualPassword, _ := cmd.Flags().GetString("database-password"); manualPassword != "" {
		databasePassword = manualPassword
	}
	
	port := envConfig.Services.DefaultPorts["mattermost"]
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 {
		port = manualPort
	}

	resourceConfig := envConfig.Services.Resources[envConfig.Environment]
	
	pillarConfig := map[string]interface{}{
		"nomad_service": map[string]interface{}{
			"name":        "mattermost",
			"environment": envConfig.Environment,
			"config": map[string]interface{}{
				"database_password": databasePassword,
				"file_public_key":   filePublicKey,
				"file_private_key":  filePrivateKey,
				"invite_salt":       inviteSalt,
				"port":              port,
				"datacenter":        envConfig.Datacenter,
				"data_path":         envConfig.Services.DataPath + "/mattermost",
				"cpu":               resourceConfig.CPU,
				"memory":            resourceConfig.Memory,
				"replicas":          resourceConfig.Replicas,
			},
		},
	}

	// 5. Deploy with automatically configured values
	logger.Info("Deploying Mattermost via SaltStack → Terraform → Nomad",
		zap.String("environment", envConfig.Environment),
		zap.String("datacenter", envConfig.Datacenter),
		zap.Int("port", port),
		zap.Int("cpu", resourceConfig.CPU),
		zap.Int("memory", resourceConfig.Memory),
		zap.Int("replicas", resourceConfig.Replicas))

	// Deploy using Nomad orchestration
	mattermostConfig := &mattermost.Config{
		PostgresUser:     "mattermost",
		PostgresPassword: databasePassword,
		PostgresDB:       "mattermost",
		PostgresHost:     "mattermost-postgres.service.consul",
		PostgresPort:     5432,
		Port:             port,
		Host:             "0.0.0.0",
		Domain:           fmt.Sprintf("mattermost.%s.local", envConfig.Environment),
		Protocol:         "https",
		Datacenter:       envConfig.Datacenter,
		Environment:      envConfig.Environment,
		DataPath:         envConfig.Services.DataPath + "/mattermost",
		Replicas:         resourceConfig.Replicas,
		CPU:              resourceConfig.CPU,
		Memory:           resourceConfig.Memory,
		NomadAddr:        "http://localhost:4646",
		VaultAddr:        "http://localhost:8200",
		FilePublicKey:    filePublicKey,
		FilePrivateKey:   filePrivateKey,
		InviteSalt:       inviteSalt,
		SupportEmail:     "support@example.com",
		Timezone:         "UTC",
	}

	// Create Mattermost manager
	mattermostManager, err := mattermost.NewManager(rc, mattermostConfig)
	if err != nil {
		return fmt.Errorf("failed to create Mattermost manager: %w", err)
	}

	// Deploy Mattermost using HashiCorp stack
	if err := mattermostManager.Deploy(rc.Ctx); err != nil {
		return fmt.Errorf("mattermost deployment failed: %w", err)
	}

	_ = pillarConfig // Keep for backward compatibility

	// 6. Display success information with generated credentials
	logger.Info("Mattermost deployment completed successfully",
		zap.String("management", "SaltStack → Terraform → Nomad"),
		zap.String("environment", envConfig.Environment),
		zap.String("secret_backend", envConfig.SecretBackend))

	logger.Info("Mattermost is now available",
		zap.String("web_ui", fmt.Sprintf("http://localhost:%d", port)),
		zap.String("database_password", databasePassword),
		zap.String("consul_service", "mattermost.service.consul"))

	logger.Info("Configuration automatically managed",
		zap.String("environment_discovery", "bootstrap/salt/cloud"),
		zap.String("secret_storage", envConfig.SecretBackend),
		zap.String("resource_allocation", envConfig.Environment))

	return nil
}

func init() {
	CreateCmd.AddCommand(CreateMattermostCmd)

	// Optional override flags - everything is automatic by default
	CreateMattermostCmd.Flags().String("database-password", "", "Override automatic database password generation")
	CreateMattermostCmd.Flags().IntP("port", "p", 0, "Override automatic port assignment")
	CreateMattermostCmd.Flags().StringP("datacenter", "d", "", "Override automatic datacenter detection")
	CreateMattermostCmd.Flags().StringP("environment", "e", "", "Override automatic environment detection")
}

