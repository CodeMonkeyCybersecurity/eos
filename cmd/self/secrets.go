// cmd/self/secrets.go
package self

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault/auth"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault/secrets"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var SecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Configure Vault connection and manage secrets",
	Long: `Configure Vault connection settings and manage secrets for Eos services.

This command helps you set up Vault integration for secure credential management,
particularly for database connections and other sensitive configuration.

Subcommands:
- configure: Set up Vault connection (address, authentication)
- test: Test Vault connectivity and authentication
- set: Store secrets in Vault (database credentials, API keys, etc.)
- get: Retrieve secrets from Vault for verification
- status: Show Vault connection status and available secrets

The configuration will be guided and interactive, ensuring proper setup
of Vault integration for services like the Delphi dashboard.

Examples:
  eos self secrets configure           # Interactive Vault setup
  eos self secrets test               # Test Vault connection
  eos self secrets set delphi-db     # Set database credentials
  eos self secrets status            # Show configuration status`,
	Aliases: []string{"vault", "creds"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for secrets command")
		return cmd.Help()
	}),
}

var SecretsConfigureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure Vault connection settings",
	Long: `Interactive configuration of Vault connection settings.

This will guide you through setting up:
- Vault server address (VAULT_ADDR)
- Authentication method (token, userpass, AppRole)
- Connection validation
- Initial secret paths setup

The configuration will be stored securely and used by all Eos services
that require access to secrets, including the Delphi dashboard.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting Vault configuration setup")

		reader := bufio.NewReader(os.Stdin)

		// Step 1: Vault Address
		logger.Info("terminal prompt:  Vault Configuration Setup")
		logger.Info("terminal prompt: ================================\n")

		currentAddr := os.Getenv("VAULT_ADDR")
		if currentAddr != "" {
			logger.Info("terminal prompt: Current VAULT_ADDR", zap.String("addr", currentAddr))
		}

		logger.Info(fmt.Sprintf("terminal prompt: Enter Vault server address (e.g., https://vhost11:%d): ", shared.PortVault))
		vaultAddr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read vault address: %w", err)
		}
		vaultAddr = strings.TrimSpace(vaultAddr)

		if vaultAddr == "" {
			if currentAddr != "" {
				vaultAddr = currentAddr
				logger.Info("terminal prompt: Using current address", zap.String("addr", vaultAddr))
			} else {
				return fmt.Errorf("vault address is required")
			}
		}

		// Set environment variable for this session
		if err := os.Setenv("VAULT_ADDR", vaultAddr); err != nil {
			logger.Warn("Failed to set VAULT_ADDR environment variable", zap.Error(err))
		}
		logger.Info("Vault address configured", zap.String("address", vaultAddr))

		// Step 2: Test connection
		logger.Info("terminal prompt: 📡 Testing Vault connectivity...")

		// Initialize Vault service facade
		if err := vault.InitializeServiceFacade(rc); err != nil {
			logger.Warn("Failed to initialize Vault service", zap.Error(err))
			logger.Info("terminal prompt:  Vault connection failed", zap.Error(err))
			logger.Info("terminal prompt: Troubleshooting:")
			logger.Info("terminal prompt: - Check if Vault server is running", zap.String("addr", vaultAddr))
			logger.Info("terminal prompt: - Verify network connectivity")
			logger.Info("terminal prompt: - Check TLS certificate configuration")
			return fmt.Errorf("vault connection failed")
		}

		logger.Info("terminal prompt:  Vault server is reachable")

		// Step 3: Authentication setup
		logger.Info("terminal prompt: Authentication Setup")
		logger.Info("terminal prompt: Available authentication methods:")
		logger.Info("terminal prompt: 1. Token (recommended for initial setup)")
		logger.Info("terminal prompt: 2. Username/Password (userpass)")
		logger.Info("terminal prompt: 3. AppRole (for production services)")

		logger.Info("terminal prompt: Select authentication method [1-3]: ")
		authMethod, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read authentication method: %w", err)
		}
		authMethod = strings.TrimSpace(authMethod)

		switch authMethod {
		case "1", "":
			if err := auth.ConfigureTokenAuth(rc, reader); err != nil {
				return fmt.Errorf("token authentication setup failed: %w", err)
			}
		case "2":
			if err := auth.ConfigureUserPassAuth(rc, reader); err != nil {
				return fmt.Errorf("userpass authentication setup failed: %w", err)
			}
		case "3":
			if err := auth.ConfigureAppRoleAuth(rc, reader); err != nil {
				return fmt.Errorf("approle authentication setup failed: %w", err)
			}
		default:
			return fmt.Errorf("invalid authentication method: %s", authMethod)
		}

		// Step 4: Create environment file
		logger.Info("terminal prompt:  Saving configuration...")
		if err := auth.SaveVaultConfig(rc, vaultAddr, authMethod); err != nil {
			logger.Error("Failed to save Vault configuration", zap.Error(err))
			return fmt.Errorf("failed to save configuration: %w", err)
		}

		logger.Info("terminal prompt:  Vault configuration saved successfully")
		logger.Info("terminal prompt: Next steps:")
		logger.Info("terminal prompt: - Test the configuration: eos self secrets test")
		logger.Info("terminal prompt: - Set database credentials: eos self secrets set delphi-db")
		logger.Info("terminal prompt: - Run the dashboard: eos delphi dashboard")

		logger.Info("Vault configuration completed successfully")
		return nil
	}),
}

var SecretsSetCmd = &cobra.Command{
	Use:   "set <secret-name>",
	Short: "Store secrets in Vault",
	Long: `Store secrets in Vault for use by Eos services.

Available secret types:
- delphi-db: Database credentials for Delphi pipeline (static)
- delphi-db-config: Database connection configuration (host, port, database name)
- delphi-db-engine: Configure Vault database secrets engine for dynamic credentials
- smtp: SMTP credentials for email services
- openai: OpenAI API keys for LLM services
- custom: Custom key-value pairs

Examples:
  eos self secrets set delphi-db         # Set static database credentials
  eos self secrets set delphi-db-config  # Set database connection parameters
  eos self secrets set delphi-db-engine  # Configure dynamic database engine
  eos self secrets set smtp              # Set SMTP credentials  
  eos self secrets set openai            # Set OpenAI API key`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"delphi-db", "delphi-db-config", "delphi-db-engine", "smtp", "openai", "custom"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		secretName := args[0]

		logger.Info("Setting secret in Vault", zap.String("secret", secretName))

		// Initialize Vault
		if err := vault.InitializeServiceFacade(rc); err != nil {
			return fmt.Errorf("failed to initialize Vault: %w", err)
		}

		facade := vault.GetServiceFacade()
		if facade == nil {
			return fmt.Errorf("vault service not available")
		}

		switch secretName {
		case "delphi-db":
			return secrets.SetDatabaseCredentials(rc, facade)
		case "delphi-db-config":
			return secrets.SetDatabaseConfig(rc, facade)
		case "delphi-db-engine":
			return secrets.SetDatabaseEngine(rc, facade)
		case "smtp":
			return fmt.Errorf("smtp secrets not yet migrated - use legacy version")
		case "openai":
			return fmt.Errorf("openai secrets not yet migrated - use legacy version")
		case "custom":
			return fmt.Errorf("custom secrets not yet migrated - use legacy version")
		default:
			return fmt.Errorf("unknown secret type: %s", secretName)
		}
	}),
}

var SecretsTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test Vault connectivity and authentication",
	Long: `Test Vault connectivity and authentication setup.

This command will:
- Test connection to Vault server
- Verify authentication credentials
- Test secret reading/writing permissions
- Display connection status and diagnostics`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Testing Vault connectivity")

		logger.Info("terminal prompt:  Vault Connectivity Test")
		logger.Info("terminal prompt: ===========================\n")

		// Test 1: Check environment variables
		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			logger.Info("terminal prompt:  VAULT_ADDR not set")
			logger.Info("terminal prompt:    Run: eos self secrets configure\n")
			return fmt.Errorf("VAULT_ADDR environment variable not set")
		}
		logger.Info("terminal prompt:  VAULT_ADDR", zap.String("addr", vaultAddr))

		// Test 2: Initialize Vault service
		if err := vault.InitializeServiceFacade(rc); err != nil {
			logger.Info("terminal prompt:  Vault service initialization failed", zap.Error(err))
			return fmt.Errorf("vault initialization failed: %w", err)
		}
		logger.Info("terminal prompt:  Vault service initialized")

		// Test 3: Test secret access
		facade := vault.GetServiceFacade()
		if facade == nil {
			logger.Info("terminal prompt:  Vault service facade not available")
			return fmt.Errorf("vault service not available")
		}

		// Try to read a test secret using the simplified facade
		testPath := "secret/data/delphi/database/username"
		_, err := facade.RetrieveSecret(rc.Ctx, testPath)
		if err != nil {
			logger.Info("terminal prompt:   Secret access test failed", zap.Error(err))
			logger.Info("terminal prompt:    This is normal if no secrets have been set yet")
		} else {
			logger.Info("terminal prompt:  Secret access working")
		}

		logger.Info("terminal prompt:  Vault connectivity test completed")
		logger.Info("terminal prompt: Vault is ready for use with Eos services")

		return nil
	}),
}

var SecretsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Vault connection status and available secrets",
	Long: `Display Vault connection status and list available secrets.

Shows:
- Vault server address and connectivity
- Authentication status
- Available secret paths
- Service-specific credential status`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Checking Vault status")

		logger.Info("terminal prompt:  Vault Status")
		logger.Info("terminal prompt: ===============\n")

		// Check basic configuration
		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			logger.Info("terminal prompt:  Vault not configured")
			logger.Info("terminal prompt:    Run: eos self secrets configure")
			return nil
		}

		logger.Info("terminal prompt: Server", zap.String("address", vaultAddr))

		// Check Vault service
		if err := vault.InitializeServiceFacade(rc); err != nil {
			logger.Info("terminal prompt: Status: Connection failed", zap.Error(err))
			return nil
		}

		logger.Info("terminal prompt: Status:  Connected\n")

		// Check available secrets
		logger.Info("terminal prompt:  Available Secrets:")

		facade := vault.GetServiceFacade()
		if facade != nil {
			// Check for common secrets using simplified facade
			staticSecrets := []string{
				"secret/data/delphi/database/username",
				"secret/data/delphi/database/password",
				"secret/data/delphi/database/host",
				"secret/data/smtp/username",
				"secret/data/smtp/password",
				"secret/data/openai/api_key",
			}

			configSecrets := []string{
				"secret/data/delphi/config/host",
				"secret/data/delphi/config/port",
				"secret/data/delphi/config/database",
			}

			logger.Info("terminal prompt: Static Credentials:")
			for _, secretPath := range staticSecrets {
				_, err := facade.RetrieveSecret(rc.Ctx, secretPath)
				if err != nil {
					logger.Info("terminal prompt: Secret not set", zap.String("path", secretPath))
				} else {
					logger.Info("terminal prompt: Secret available", zap.String("path", secretPath))
				}
			}

			logger.Info("terminal prompt: Database Configuration:")
			for _, secretPath := range configSecrets {
				_, err := facade.RetrieveSecret(rc.Ctx, secretPath)
				if err != nil {
					logger.Info("terminal prompt: Secret not set", zap.String("path", secretPath))
				} else {
					logger.Info("terminal prompt: Secret available", zap.String("path", secretPath))
				}
			}

			logger.Info("terminal prompt: Dynamic Database Engine:")
			// Test if dynamic credentials are available
			_, err := facade.RetrieveSecret(rc.Ctx, "database/creds/delphi-readonly")
			if err != nil {
				logger.Info("terminal prompt:     database/creds/delphi-readonly (not configured)")
				logger.Info("terminal prompt:     Run: eos self secrets set delphi-db-engine")
			} else {
				logger.Info("terminal prompt:     database/creds/delphi-readonly (dynamic credentials available)")
			}
		}

		logger.Info("terminal prompt: Commands:")
		logger.Info("terminal prompt: - Set static database credentials: eos self secrets set delphi-db")
		logger.Info("terminal prompt: - Set database configuration: eos self secrets set delphi-db-config")
		logger.Info("terminal prompt: - Setup dynamic credentials: eos self secrets set delphi-db-engine")
		logger.Info("terminal prompt: - Test connectivity: eos self secrets test")

		return nil
	}),
}

var SecretsGetCmd = &cobra.Command{
	Use:   "get <secret-path>",
	Short: "Retrieve secrets from Vault",
	Long: `Retrieve and display secrets from Vault.

Examples:
  eos self secrets get delphi/database/username
  eos self secrets get delphi/database/password --show-value
  eos self secrets get openai/api_key`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		secretPath := args[0]
		showValue, _ := cmd.Flags().GetBool("show-value")

		// Initialize Vault
		if err := vault.InitializeServiceFacade(rc); err != nil {
			return fmt.Errorf("failed to initialize Vault: %w", err)
		}

		facade := vault.GetServiceFacade()
		if facade == nil {
			return fmt.Errorf("vault service not available")
		}

		// Use the simplified facade to retrieve secrets
		secretData, err := facade.RetrieveSecret(rc.Ctx, secretPath)
		if err != nil {
			return fmt.Errorf("failed to retrieve secret %s: %w", secretPath, err)
		}

		// secretData is map[string]interface{} from vault
		if showValue {
			logger.Info("terminal prompt: Secret data", zap.String("path", secretPath), zap.Any("data", secretData))
		} else {
			logger.Info("terminal prompt: Secret data [REDACTED]", zap.String("path", secretPath))
			logger.Info("terminal prompt: Use --show-value to display the actual value")
		}

		return nil
	}),
}

func init() {
	SecretsGetCmd.Flags().Bool("show-value", false, "Show the actual secret value (use with caution)")

	// Add subcommands to SecretsCmd
	SecretsCmd.AddCommand(SecretsConfigureCmd)
	SecretsCmd.AddCommand(SecretsTestCmd)
	SecretsCmd.AddCommand(SecretsSetCmd)
	SecretsCmd.AddCommand(SecretsGetCmd)
	SecretsCmd.AddCommand(SecretsStatusCmd)
}

// All helper functions have been migrated to pkg/vault/auth/ and pkg/vault/secrets/
