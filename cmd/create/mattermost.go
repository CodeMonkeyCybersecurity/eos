// cmd/create/mattermost.go
package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
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

	if err := saltstack.ApplySaltStateWithPillar(rc, "nomad.services", pillarConfig); err != nil {
		return fmt.Errorf("Mattermost deployment failed: %w", err)
	}

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

