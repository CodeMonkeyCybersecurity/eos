// cmd/secure/credentials.go

package secure

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var credentialsCmd = &cobra.Command{
	Use:   "credentials [service]",
	Short: "Migrate service credentials to Vault",
	Long: `Migrate plaintext credentials to secure Vault storage with automated rotation.

Supported services:
  wazuh       - Migrate Wazuh default credentials to Vault
  postgresql  - Migrate PostgreSQL credentials to Vault
  custom      - Migrate custom service credentials

Examples:
  eos secure credentials wazuh --version=4.10.1 --type=single-node
  eos secure credentials postgresql --database=mydb
  eos secure credentials custom --service=myapp --vault-path=myapp/creds`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		serviceName := args[0]
		logger.Info("Starting credential security migration", 
			zap.String("service", serviceName))

		// Get command flags
		vaultPath, _ := cmd.Flags().GetString("vault-path")
		hashRequired, _ := cmd.Flags().GetBool("hash")
		policies, _ := cmd.Flags().GetStringSlice("policies")

		switch serviceName {
		case "wazuh":
			return handleWazuhCredentials(rc, cmd)
		case "postgresql":
			return handlePostgreSQLCredentials(rc, cmd)
		case "custom":
			return handleCustomCredentials(rc, cmd, vaultPath, hashRequired, policies)
		default:
			logger.Error("Unsupported service", zap.String("service", serviceName))
			return cmd.Help()
		}
	}),
}

func handleWazuhCredentials(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Migrating Wazuh credentials to Vault")

	// Get Wazuh-specific flags
	version, _ := cmd.Flags().GetString("version")
	deploymentType, _ := cmd.Flags().GetString("type")
	workingDir, _ := cmd.Flags().GetString("working-dir")

	if version == "" {
		version = "4.10.1" // Default version
	}
	if deploymentType == "" {
		deploymentType = "single-node" // Default deployment type
	}

	config := security.WazuhCredentialConfig{
		Version:        version,
		DeploymentType: deploymentType,
		WorkingDir:     workingDir,
	}

	return security.ManageWazuhCredentials(rc, config)
}

func handlePostgreSQLCredentials(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Migrating PostgreSQL credentials to Vault")

	// Get PostgreSQL-specific flags
	database, _ := cmd.Flags().GetString("database")
	host, _ := cmd.Flags().GetString("host")
	port, _ := cmd.Flags().GetString("port")

	if database == "" {
		database = "postgres" // Default database
	}
	_ = database // TODO: Use database in credential generation
	if host == "" {
		host = "localhost" // Default host
	}
	_ = host // TODO: Use host in credential generation
	if port == "" {
		port = "5432" // Default port
	}
	_ = port // TODO: Use port in credential generation

	config := security.CredentialConfig{
		Service:   "postgresql",
		VaultPath: "postgresql/credentials",
		Credentials: map[string]string{
			"admin":    "admin_password",
			"app_user": "application_password",
			"readonly": "readonly_password",
		},
		HashRequired: false, // PostgreSQL uses its own hashing
		Policies:     []string{"postgresql-admin", "postgresql-app"},
	}

	// Assess current state
	assessment, err := security.AssessCredentialSecurity(rc, config)
	if err != nil {
		return err
	}

	logger.Info("PostgreSQL credential assessment completed",
		zap.Int("config_files", len(assessment.ConfigFiles)),
		zap.Int("weak_credentials", len(assessment.WeakCredentials)))

	// Migrate to Vault
	return security.MigrateCredentialsToVault(rc, config)
}

func handleCustomCredentials(rc *eos_io.RuntimeContext, cmd *cobra.Command, vaultPath string, hashRequired bool, policies []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Migrating custom service credentials to Vault")

	serviceName, _ := cmd.Flags().GetString("service")
	credentialNames, _ := cmd.Flags().GetStringSlice("credentials")

	if serviceName == "" {
		serviceName = "custom"
	}
	if vaultPath == "" {
		vaultPath = serviceName + "/credentials"
	}

	// Build credential mapping
	credentials := make(map[string]string)
	for _, credName := range credentialNames {
		credentials[credName] = "password"
	}

	// Default credentials if none specified
	if len(credentials) == 0 {
		credentials = map[string]string{
			"admin": "admin_password",
			"user":  "user_password",
		}
	}

	config := security.CredentialConfig{
		Service:      serviceName,
		VaultPath:    vaultPath,
		Credentials:  credentials,
		HashRequired: hashRequired,
		Policies:     policies,
	}

	logger.Info("Custom credential configuration",
		zap.String("service", serviceName),
		zap.String("vault_path", vaultPath),
		zap.Bool("hash_required", hashRequired),
		zap.Int("credential_count", len(credentials)))

	// Assess current state
	assessment, err := security.AssessCredentialSecurity(rc, config)
	if err != nil {
		return err
	}

	logger.Info("Custom credential assessment completed",
		zap.Int("config_files", len(assessment.ConfigFiles)),
		zap.Int("weak_credentials", len(assessment.WeakCredentials)))

	// Migrate to Vault
	return security.MigrateCredentialsToVault(rc, config)
}

func init() {
	// Add credentials command to secure
	SecureCmd.AddCommand(credentialsCmd)

	// Wazuh-specific flags
	credentialsCmd.Flags().String("version", "", "Wazuh version (e.g., 4.10.1)")
	credentialsCmd.Flags().String("type", "", "Deployment type (single-node or multi-node)")
	credentialsCmd.Flags().String("working-dir", "", "Working directory containing docker-compose.yml")

	// PostgreSQL-specific flags
	credentialsCmd.Flags().String("database", "", "PostgreSQL database name")
	credentialsCmd.Flags().String("host", "", "PostgreSQL host")
	credentialsCmd.Flags().String("port", "", "PostgreSQL port")

	// Custom service flags
	credentialsCmd.Flags().String("service", "", "Custom service name")
	credentialsCmd.Flags().String("vault-path", "", "Vault path for storing credentials")
	credentialsCmd.Flags().Bool("hash", false, "Generate hashed versions of credentials")
	credentialsCmd.Flags().StringSlice("policies", []string{}, "Vault policies to create")
	credentialsCmd.Flags().StringSlice("credentials", []string{}, "Credential names to generate")
}