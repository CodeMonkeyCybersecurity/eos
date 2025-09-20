// cmd/create/jenkins.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	// TODO: Replace with Nomad orchestration
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateJenkinsCmd represents the Jenkins installation command.
var CreateJenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Deploy Jenkins CI/CD platform using Nomad orchestration",
	Long: `Deploy Jenkins CI/CD platform using the SaltStack → Terraform → Nomad architecture.

This command provides a complete Jenkins deployment with automatic configuration:
- Automatic environment discovery (production/staging/development)
- Secure credential generation and storage (Vault/SaltStack/file)
- Container orchestration via Nomad
- Service discovery via Consul
- Persistent data storage
- Health monitoring and recovery
- Production-ready configuration

The deployment is managed through Terraform state ensuring consistent and reliable operations.

Examples:
  eos create jenkins                                # Deploy with automatic configuration
  eos create jenkins --admin-password secret123    # Override admin password
  eos create jenkins --port 8080                   # Override port
  eos create jenkins --datacenter production       # Override datacenter`,
	RunE: eos.Wrap(runCreateJenkins),
}
func runCreateJenkins(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	logger.Info("Starting Jenkins deployment with automatic configuration")

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
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 && manualPort != shared.PortJenkins {
		logger.Info("Using manually provided port", zap.Int("port", manualPort))
	}

	// 3. Get or generate secrets automatically
	secretManager, err := secrets.NewSecretManager(rc, envConfig)
	if err != nil {
		return fmt.Errorf("secret manager initialization failed: %w", err)
	}

	requiredSecrets := map[string]secrets.SecretType{
		"admin_password": secrets.SecretTypePassword,
		"api_token":      secrets.SecretTypeAPIKey,
		"jwt_secret":     secrets.SecretTypeJWT,
	}

	serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("jenkins", requiredSecrets)
	if err != nil {
		return fmt.Errorf("secret generation failed: %w", err)
	}

	// 4. Build configuration with discovered/generated values
	adminPassword := serviceSecrets.Secrets["admin_password"].(string)
	apiToken := serviceSecrets.Secrets["api_token"].(string)
	jwtSecret := serviceSecrets.Secrets["jwt_secret"].(string)
	
	// Allow manual overrides
	if manualPassword, _ := cmd.Flags().GetString("admin-password"); manualPassword != "" {
		adminPassword = manualPassword
	}
	
	port := envConfig.Services.DefaultPorts["jenkins"]
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 {
		port = manualPort
	}

	resourceConfig := envConfig.Services.Resources[envConfig.Environment]
	
	pillarConfig := map[string]interface{}{
		"nomad_service": map[string]interface{}{
			"name":        "jenkins",
			"environment": envConfig.Environment,
			"config": map[string]interface{}{
				"admin_password": adminPassword,
				"api_token":      apiToken,
				"jwt_secret":     jwtSecret,
				"port":          port,
				"datacenter":    envConfig.Datacenter,
				"data_path":     envConfig.Services.DataPath + "/jenkins",
				"cpu":           resourceConfig.CPU,
				"memory":        resourceConfig.Memory,
				"replicas":      resourceConfig.Replicas,
			},
		},
	}

	// 5. Deploy with automatically configured values
	logger.Info("Deploying Jenkins via SaltStack → Terraform → Nomad",
		zap.String("environment", envConfig.Environment),
		zap.String("datacenter", envConfig.Datacenter),
		zap.Int("port", port),
		zap.Int("cpu", resourceConfig.CPU),
		zap.Int("memory", resourceConfig.Memory),
		zap.Int("replicas", resourceConfig.Replicas))

	// TODO: Replace with Nomad orchestration when implemented
	logger.Info("Jenkins deployment placeholder - Nomad orchestration not implemented yet")
	_ = pillarConfig // Suppress unused variable warning
	
	// TODO: When Nomad implementation is complete, add success logging:
	// - Jenkins web UI availability
	// - Generated admin credentials  
	// - Consul service registration
	// - Configuration management details
	
	return fmt.Errorf("jenkins deployment not implemented with Nomad yet")
}


func init() {
	CreateCmd.AddCommand(CreateJenkinsCmd)
	
	// Optional override flags - everything is automatic by default
	CreateJenkinsCmd.Flags().String("admin-password", "", "Override automatic admin password generation")
	CreateJenkinsCmd.Flags().IntP("port", "p", 0, "Override automatic port assignment")
	CreateJenkinsCmd.Flags().StringP("datacenter", "d", "", "Override automatic datacenter detection")
	CreateJenkinsCmd.Flags().StringP("environment", "e", "", "Override automatic environment detection")
}

