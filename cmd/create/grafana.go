// cmd/create/grafana.go
package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
			Environment: "production",
			Datacenter:  "dc1",
			Region:      "us-east-1",
			VaultAddr:   fmt.Sprintf("http://localhost:%d", shared.PortVault),
		}
	}

	logger.Info("Environment discovered",
		zap.String("environment", envConfig.Environment),
		zap.String("datacenter", envConfig.Datacenter),
		zap.String("region", envConfig.Region),
		zap.String("vault_addr", envConfig.VaultAddr))

	// 2. Check for manual overrides from flags
	if manualPassword, _ := cmd.Flags().GetString("admin-password"); manualPassword != "" {
		logger.Info("Using manually provided admin password")
	}
	if manualPort, _ := cmd.Flags().GetInt("port"); manualPort != 0 && manualPort != shared.PortGrafana {
		logger.Info("Using manually provided port", zap.Int("port", manualPort))
	}

	// 3. Get or generate secrets automatically
	secretManager, err := secrets.NewManager(rc, envConfig)
	if err != nil {
		return fmt.Errorf("secret manager initialization failed: %w", err)
	}

	requiredSecrets := map[string]secrets.SecretType{
		"admin_password": secrets.SecretTypePassword,
		"secret_key":     secrets.SecretTypeToken,
	}

	serviceSecrets, err := secretManager.EnsureServiceSecrets(rc.Ctx, "grafana", requiredSecrets)
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

	nomadConfig := map[string]interface{}{
		"grafana": map[string]interface{}{
			"version":      "latest",
			"port":         port,
			"environment":  envConfig.Environment,
			"datacenter":   envConfig.Datacenter,
			"cpu":          resourceConfig.CPU,
			"memory":       resourceConfig.Memory,
			"replicas":     resourceConfig.Replicas,
			"admin_user":   "admin",
			"admin_pass":   adminPassword,
			"secret_key":   secretKey,
			"database_url": "sqlite3:///grafana.db",
		},
	}
	_ = nomadConfig // TODO: Use for Nomad job deployment

	// 5. Deploy with automatically configured values
	logger.Info("Deploying Grafana via Nomad orchestration",
		zap.String("environment", envConfig.Environment),
		zap.String("datacenter", envConfig.Datacenter),
		zap.Int("port", port),
		zap.Int("cpu", resourceConfig.CPU),
		zap.Int("memory", resourceConfig.Memory),
		zap.Int("replicas", resourceConfig.Replicas))

	// Deploy using Nomad orchestration instead of
	logger.Info("Deploying Grafana using Nomad orchestration")
	// TODO: Implement Nomad job deployment for Grafana
	return fmt.Errorf("grafana Nomad deployment not yet implemented")
}

func init() {
	CreateCmd.AddCommand(CreateGrafanaCmd)

	// Optional override flags - everything is automatic by default
	CreateGrafanaCmd.Flags().String("admin-password", "", "Override automatic admin password generation")
	CreateGrafanaCmd.Flags().IntP("port", "p", 0, "Override automatic port assignment")
	CreateGrafanaCmd.Flags().StringP("datacenter", "d", "", "Override automatic datacenter detection")
	CreateGrafanaCmd.Flags().StringP("environment", "e", "", "Override automatic environment detection")
}
