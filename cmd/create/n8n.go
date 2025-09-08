// cmd/create/n8n.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/n8n"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateN8nCmd represents the n8n installation command
var CreateN8nCmd = &cobra.Command{
	Use:   "n8n",
	Short: "Deploy n8n workflow automation platform using Nomad orchestration",
	Long: `Deploy n8n workflow automation platform using the SaltStack → Terraform → Nomad architecture.

n8n is a powerful workflow automation tool that allows you to connect different services
and automate tasks. This command provides a complete production-ready deployment with:

- Automatic environment discovery (production/staging/development)
- Secure credential generation and storage (Vault/SaltStack/file)
- PostgreSQL database with automated setup
- Redis for job queuing and horizontal scaling
- Container orchestration via Nomad
- Service discovery via Consul
- Nginx reverse proxy with SSL support
- Persistent data storage
- Health monitoring and recovery
- Production-ready configuration

The deployment includes:
- n8n main service with web UI
- n8n workers for processing workflows at scale
- PostgreSQL 15 database with proper security
- Redis for job queuing
- Nginx reverse proxy with automatic SSL
- Automated backup service with retention policies

Examples:
  eos create n8n                                    # Deploy with automatic configuration
  eos create n8n --admin-password secret123         # Override admin password
  eos create n8n --port 8147                        # Override port (default: 8147)
  eos create n8n --datacenter production            # Override datacenter
  eos create n8n --domain n8n.example.com           # Custom domain
  eos create n8n --workers 3                        # Scale workers for high load`,
	RunE: eos.Wrap(runCreateN8n),
}

func runCreateN8n(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	logger.Info("Starting n8n deployment with automatic configuration")

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
	if manualPassword, _ := cmd.Flags().GetString("admin-password"); manualPassword != "" {
		logger.Info("Using manually provided admin password")
	}
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 && manualPort != shared.PortN8n {
		logger.Info("Using manually provided port", zap.Int("port", manualPort))
	}
	if manualDomain, _ := cmd.Flags().GetString("domain"); manualDomain != "" {
		logger.Info("Using manually provided domain", zap.String("domain", manualDomain))
	}

	// 3. Get or generate secrets automatically
	secretManager, err := secrets.NewSecretManager(rc, envConfig)
	if err != nil {
		return fmt.Errorf("secret manager initialization failed: %w", err)
	}

	requiredSecrets := map[string]secrets.SecretType{
		"admin_password":        secrets.SecretTypePassword,
		"encryption_key":        secrets.SecretTypeToken,
		"jwt_secret":           secrets.SecretTypeJWT,
		"postgres_password":    secrets.SecretTypePassword,
		"postgres_user":        secrets.SecretTypeAPIKey,
		"basic_auth_password":  secrets.SecretTypePassword,
	}

	serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("n8n", requiredSecrets)
	if err != nil {
		return fmt.Errorf("secret generation failed: %w", err)
	}

	// 4. Build configuration with discovered/generated values
	adminPassword := serviceSecrets.Secrets["admin_password"].(string)
	encryptionKey := serviceSecrets.Secrets["encryption_key"].(string)
	jwtSecret := serviceSecrets.Secrets["jwt_secret"].(string)
	postgresPassword := serviceSecrets.Secrets["postgres_password"].(string)
	postgresUser := serviceSecrets.Secrets["postgres_user"].(string)
	basicAuthPassword := serviceSecrets.Secrets["basic_auth_password"].(string)
	
	// Allow manual overrides
	if manualPassword, _ := cmd.Flags().GetString("admin-password"); manualPassword != "" {
		adminPassword = manualPassword
	}
	
	port := shared.PortN8n
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 {
		port = manualPort
	}

	domain, _ := cmd.Flags().GetString("domain")
	if domain == "" {
		domain = "n8n.local"
	}

	workers, _ := cmd.Flags().GetInt("workers")
	if workers == 0 {
		workers = 1
	}

	resourceConfig := envConfig.Services.Resources[envConfig.Environment]
	
	// 5. Create n8n configuration
	n8nConfig := &n8n.Config{
		AdminPassword:     adminPassword,
		EncryptionKey:     encryptionKey,
		JWTSecret:        jwtSecret,
		PostgresUser:     postgresUser,
		PostgresPassword: postgresPassword,
		BasicAuthUser:    "admin",
		BasicAuthPassword: basicAuthPassword,
		Domain:           domain,
		Port:            port,
		Workers:         workers,
		Datacenter:      envConfig.Datacenter,
		Environment:     envConfig.Environment,
		DataPath:        envConfig.Services.DataPath + "/n8n",
		CPU:             resourceConfig.CPU,
		Memory:          resourceConfig.Memory,
	}

	pillarConfig := map[string]interface{}{
		"nomad_service": map[string]interface{}{
			"name":        "n8n",
			"environment": envConfig.Environment,
			"config":      n8nConfig.ToPillarData(),
		},
	}

	// 6. Deploy with automatically configured values
	logger.Info("Deploying n8n via SaltStack → Terraform → Nomad",
		zap.String("environment", envConfig.Environment),
		zap.String("datacenter", envConfig.Datacenter),
		zap.Int("port", port),
		zap.String("domain", domain),
		zap.Int("workers", workers),
		zap.Int("cpu", resourceConfig.CPU),
		zap.Int("memory", resourceConfig.Memory))

	if err := saltstack.ApplySaltStateWithPillar(rc, "nomad.services", pillarConfig); err != nil {
		return fmt.Errorf("n8n deployment failed: %w", err)
	}

	// 7. Display success information with generated credentials
	logger.Info("n8n deployment completed successfully",
		zap.String("management", "SaltStack → Terraform → Nomad"),
		zap.String("environment", envConfig.Environment),
		zap.String("secret_backend", envConfig.SecretBackend))

	logger.Info("n8n is now available",
		zap.String("web_ui", fmt.Sprintf("https://%s", domain)),
		zap.String("internal_port", fmt.Sprintf("http://localhost:%d", port)),
		zap.String("username", "admin"),
		zap.String("password", adminPassword),
		zap.String("consul_service", "n8n.service.consul"))

	logger.Info("Configuration automatically managed",
		zap.String("environment_discovery", "bootstrap/salt/cloud"),
		zap.String("secret_storage", envConfig.SecretBackend),
		zap.String("resource_allocation", envConfig.Environment),
		zap.Int("worker_instances", workers))

	logger.Info("Next steps",
		zap.String("access", fmt.Sprintf("Visit https://%s to access n8n", domain)),
		zap.String("login", "Use admin credentials shown above"),
		zap.String("scaling", "Use --workers flag to scale for high load"),
		zap.String("monitoring", "Check Consul UI for service health"))

	return nil
}

func init() {
	CreateCmd.AddCommand(CreateN8nCmd)
	
	// Optional override flags - everything is automatic by default
	CreateN8nCmd.Flags().String("admin-password", "", "Override automatic admin password generation")
	CreateN8nCmd.Flags().IntP("port", "p", 0, "Override automatic port assignment (default: 8147)")
	CreateN8nCmd.Flags().StringP("datacenter", "d", "", "Override automatic datacenter detection")
	CreateN8nCmd.Flags().StringP("environment", "e", "", "Override automatic environment detection")
	CreateN8nCmd.Flags().String("domain", "", "Domain name for n8n (default: n8n.local)")
	CreateN8nCmd.Flags().Int("workers", 1, "Number of n8n worker instances for scaling")
}
