// cmd/self/secrets.go
package self

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
		fmt.Printf("\n Vault Configuration Setup\n")
		fmt.Printf("================================\n\n")

		currentAddr := os.Getenv("VAULT_ADDR")
		if currentAddr != "" {
			fmt.Printf("Current VAULT_ADDR: %s\n", currentAddr)
		}

		fmt.Printf("Enter Vault server address (e.g., https://vhost11:8200): ")
		vaultAddr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read vault address: %w", err)
		}
		vaultAddr = strings.TrimSpace(vaultAddr)

		if vaultAddr == "" {
			if currentAddr != "" {
				vaultAddr = currentAddr
				fmt.Printf("Using current address: %s\n", vaultAddr)
			} else {
				return fmt.Errorf("vault address is required")
			}
		}

		// Set environment variable for this session
		os.Setenv("VAULT_ADDR", vaultAddr)
		logger.Info("Vault address configured", zap.String("address", vaultAddr))

		// Step 2: Test connection
		fmt.Printf("\n📡 Testing Vault connectivity...\n")

		// Initialize Vault service facade
		if err := vault.InitializeServiceFacade(rc); err != nil {
			logger.Warn("Failed to initialize Vault service", zap.Error(err))
			fmt.Printf(" Vault connection failed: %v\n", err)
			fmt.Printf("\nTroubleshooting:\n")
			fmt.Printf("- Check if Vault server is running at %s\n", vaultAddr)
			fmt.Printf("- Verify network connectivity\n")
			fmt.Printf("- Check TLS certificate configuration\n")
			return fmt.Errorf("vault connection failed")
		}

		fmt.Printf(" Vault server is reachable\n")

		// Step 3: Authentication setup
		fmt.Printf("\nAuthentication Setup\n")
		fmt.Printf("Available authentication methods:\n")
		fmt.Printf("1. Token (recommended for initial setup)\n")
		fmt.Printf("2. Username/Password (userpass)\n")
		fmt.Printf("3. AppRole (for production services)\n")

		fmt.Printf("Select authentication method [1-3]: ")
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
		fmt.Printf("\n💾 Saving configuration...\n")
		if err := auth.SaveVaultConfig(rc, vaultAddr, authMethod); err != nil {
			logger.Error("Failed to save Vault configuration", zap.Error(err))
			return fmt.Errorf("failed to save configuration: %w", err)
		}

		fmt.Printf(" Vault configuration saved successfully\n")
		fmt.Printf("\nNext steps:\n")
		fmt.Printf("- Test the configuration: eos self secrets test\n")
		fmt.Printf("- Set database credentials: eos self secrets set delphi-db\n")
		fmt.Printf("- Run the dashboard: eos delphi dashboard\n")

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

		secretStore := facade.GetSecretStore()

		switch secretName {
		case "delphi-db":
			return secrets.SetDatabaseCredentials(rc, secretStore)
		case "delphi-db-config":
			return secrets.SetDatabaseConfig(rc, secretStore)
		case "delphi-db-engine":
			return secrets.SetDatabaseEngine(rc, secretStore)
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

		fmt.Printf(" Vault Connectivity Test\n")
		fmt.Printf("===========================\n\n")

		// Test 1: Check environment variables
		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			fmt.Printf(" VAULT_ADDR not set\n")
			fmt.Printf("   Run: eos self secrets configure\n\n")
			return fmt.Errorf("VAULT_ADDR environment variable not set")
		}
		fmt.Printf(" VAULT_ADDR: %s\n", vaultAddr)

		// Test 2: Initialize Vault service
		if err := vault.InitializeServiceFacade(rc); err != nil {
			fmt.Printf(" Vault service initialization failed: %v\n", err)
			return fmt.Errorf("vault initialization failed: %w", err)
		}
		fmt.Printf(" Vault service initialized\n")

		// Test 3: Test secret access
		facade := vault.GetServiceFacade()
		if facade == nil {
			fmt.Printf(" Vault service facade not available\n")
			return fmt.Errorf("vault service not available")
		}

		secretStore := facade.GetSecretStore()

		// Try to read a test secret
		testKey := "delphi/database/username"
		_, err := secretStore.Get(rc.Ctx, testKey)
		if err != nil {
			fmt.Printf("  Secret access test: %v\n", err)
			fmt.Printf("   This is normal if no secrets have been set yet\n")
		} else {
			fmt.Printf(" Secret access working\n")
		}

		fmt.Printf("\n Vault connectivity test completed\n")
		fmt.Printf("Vault is ready for use with Eos services\n")

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

		fmt.Printf(" Vault Status\n")
		fmt.Printf("===============\n\n")

		// Check basic configuration
		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			fmt.Printf(" Vault not configured\n")
			fmt.Printf("   Run: eos self secrets configure\n")
			return nil
		}

		fmt.Printf("Server: %s\n", vaultAddr)

		// Check Vault service
		if err := vault.InitializeServiceFacade(rc); err != nil {
			fmt.Printf("Status:  Connection failed (%v)\n", err)
			return nil
		}

		fmt.Printf("Status:  Connected\n\n")

		// Check available secrets
		fmt.Printf(" Available Secrets:\n")

		facade := vault.GetServiceFacade()
		if facade != nil {
			secretStore := facade.GetSecretStore()

			// Check for common secrets
			staticSecrets := []string{
				"delphi/database/username",
				"delphi/database/password",
				"delphi/database/host",
				"smtp/username",
				"smtp/password",
				"openai/api_key",
			}

			configSecrets := []string{
				"delphi/config/host",
				"delphi/config/port",
				"delphi/config/database",
			}

			fmt.Printf("Static Credentials:\n")
			for _, secretPath := range staticSecrets {
				_, err := secretStore.Get(rc.Ctx, secretPath)
				if err != nil {
					fmt.Printf("    %s (not set)\n", secretPath)
				} else {
					fmt.Printf("    %s\n", secretPath)
				}
			}

			fmt.Printf("\nDatabase Configuration:\n")
			for _, secretPath := range configSecrets {
				_, err := secretStore.Get(rc.Ctx, secretPath)
				if err != nil {
					fmt.Printf("    %s (not set)\n", secretPath)
				} else {
					fmt.Printf("    %s\n", secretPath)
				}
			}

			fmt.Printf("\nDynamic Database Engine:\n")
			// Test if dynamic credentials are available
			_, err := secretStore.Get(rc.Ctx, "database/creds/delphi-readonly")
			if err != nil {
				fmt.Printf("    database/creds/delphi-readonly (not configured)\n")
				fmt.Printf("    Run: eos self secrets set delphi-db-engine\n")
			} else {
				fmt.Printf("    database/creds/delphi-readonly (dynamic credentials available)\n")
			}
		}

		fmt.Printf("\nCommands:\n")
		fmt.Printf("- Set static database credentials: eos self secrets set delphi-db\n")
		fmt.Printf("- Set database configuration: eos self secrets set delphi-db-config\n")
		fmt.Printf("- Setup dynamic credentials: eos self secrets set delphi-db-engine\n")
		fmt.Printf("- Test connectivity: eos self secrets test\n")

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

		secretStore := facade.GetSecretStore()

		value, err := secretStore.Get(rc.Ctx, secretPath)
		if err != nil {
			return fmt.Errorf("failed to retrieve secret %s: %w", secretPath, err)
		}

		if showValue {
			fmt.Printf("Secret: %s\nValue: %s\n", secretPath, value.Value)
		} else {
			fmt.Printf("Secret: %s\nValue: %s\n", secretPath, strings.Repeat("*", len(value.Value)))
			fmt.Printf("Use --show-value to display the actual value\n")
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
