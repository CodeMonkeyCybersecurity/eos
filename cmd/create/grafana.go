// cmd/create/grafana.go
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

// CreateGrafanaCmd installs Grafana using Nomad orchestration
var CreateGrafanaCmd = &cobra.Command{
	Use:   "grafana",
	Short: "Install Grafana monitoring and visualization platform",
	Long: `Install Grafana using Nomad container orchestration with comprehensive configuration options.

Grafana is a powerful monitoring and visualization platform that allows you to
query, visualize, and understand your metrics. This command deploys Grafana
as a containerized service managed by Nomad with automatic service discovery
via Consul.

The deployment includes:
- Automated container lifecycle management via Nomad
- Service registration and health checks via Consul
- Persistent data storage
- Secure admin credentials
- Production-ready configuration

Examples:
  eos create grafana                                    # Install with defaults
  eos create grafana --admin-password secret123        # Custom admin password
  eos create grafana --port 3000                       # Custom port
  eos create grafana --datacenter production           # Specific datacenter`,

	RunE: eos.Wrap(runCreateGrafana),
}

func runCreateGrafana(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	logger.Info("Starting Grafana deployment with automatic configuration")

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
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 && manualPort != shared.PortGrafana {
		logger.Info("Using manually provided port", zap.Int("port", manualPort))
	}

	// 3. Get or generate secrets automatically
	secretManager, err := secrets.NewSecretManager(rc, envConfig)
	if err != nil {
		return fmt.Errorf("secret manager initialization failed: %w", err)
	}

	requiredSecrets := map[string]secrets.SecretType{
		"admin_password": secrets.SecretTypePassword,
		"secret_key":     secrets.SecretTypeToken,
	}

	serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("grafana", requiredSecrets)
	if err != nil {
		return fmt.Errorf("secret generation failed: %w", err)
	}

	// 4. Build configuration with discovered/generated values
	adminPassword := serviceSecrets.Secrets["admin_password"].(string)
	secretKey := serviceSecrets.Secrets["secret_key"].(string)
	
	// Allow manual overrides
	if manualPassword, _ := cmd.Flags().GetString("admin-password"); manualPassword != "" {
		adminPassword = manualPassword
	}
	
	port := envConfig.Services.DefaultPorts["grafana"]
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 {
		port = manualPort
	}

	resourceConfig := envConfig.Services.Resources[envConfig.Environment]
	
	pillarConfig := map[string]interface{}{
		"nomad_service": map[string]interface{}{
			"name":        "grafana",
			"environment": envConfig.Environment,
			"config": map[string]interface{}{
				"admin_password": adminPassword,
				"secret_key":     secretKey,
				"port":          port,
				"datacenter":    envConfig.Datacenter,
				"data_path":     envConfig.Services.DataPath + "/grafana",
				"cpu":           resourceConfig.CPU,
				"memory":        resourceConfig.Memory,
				"replicas":      resourceConfig.Replicas,
			},
		},
	}

	// 5. Deploy with automatically configured values
	logger.Info("Deploying Grafana via SaltStack → Terraform → Nomad",
		zap.String("environment", envConfig.Environment),
		zap.String("datacenter", envConfig.Datacenter),
		zap.Int("port", port),
		zap.Int("cpu", resourceConfig.CPU),
		zap.Int("memory", resourceConfig.Memory),
		zap.Int("replicas", resourceConfig.Replicas))

	if err := saltstack.ApplySaltStateWithPillar(rc, "nomad.services", pillarConfig); err != nil {
		return fmt.Errorf("Grafana deployment failed: %w", err)
	}

	// 6. Display success information with generated credentials
	logger.Info("Grafana deployment completed successfully",
		zap.String("management", "SaltStack → Terraform → Nomad"),
		zap.String("environment", envConfig.Environment),
		zap.String("secret_backend", envConfig.SecretBackend))

	logger.Info("Grafana is now available",
		zap.String("web_ui", fmt.Sprintf("http://localhost:%d", port)),
		zap.String("username", "admin"),
		zap.String("password", adminPassword),
		zap.String("consul_service", "grafana.service.consul"))

	logger.Info("Configuration automatically managed",
		zap.String("environment_discovery", "bootstrap/salt/cloud"),
		zap.String("secret_storage", envConfig.SecretBackend),
		zap.String("resource_allocation", envConfig.Environment))

	return nil
}


func init() {
	CreateCmd.AddCommand(CreateGrafanaCmd)

	// Optional override flags - everything is automatic by default
	CreateGrafanaCmd.Flags().String("admin-password", "", "Override automatic admin password generation")
	CreateGrafanaCmd.Flags().IntP("port", "p", 0, "Override automatic port assignment")
	CreateGrafanaCmd.Flags().StringP("datacenter", "d", "", "Override automatic datacenter detection")
	CreateGrafanaCmd.Flags().StringP("environment", "e", "", "Override automatic environment detection")
}
