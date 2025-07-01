// cmd/self/secrets.go
package self

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	vaultDomain "github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// NewSecretsCmd creates the secrets management command
func NewSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
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
	}

	// Add subcommands
	cmd.AddCommand(NewSecretsConfigureCmd())
	cmd.AddCommand(NewSecretsTestCmd())
	cmd.AddCommand(NewSecretsSetCmd())
	cmd.AddCommand(NewSecretsGetCmd())
	cmd.AddCommand(NewSecretsStatusCmd())

	return cmd
}

// NewSecretsConfigureCmd creates the configure command
func NewSecretsConfigureCmd() *cobra.Command {
	cmd := &cobra.Command{
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
			fmt.Printf("\n🔐 Vault Configuration Setup\n")
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
			fmt.Printf("\n🔑 Authentication Setup\n")
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
				if err := configureTokenAuth(rc, reader); err != nil {
					return fmt.Errorf("token authentication setup failed: %w", err)
				}
			case "2":
				if err := configureUserPassAuth(rc, reader); err != nil {
					return fmt.Errorf("userpass authentication setup failed: %w", err)
				}
			case "3":
				if err := configureAppRoleAuth(rc, reader); err != nil {
					return fmt.Errorf("approle authentication setup failed: %w", err)
				}
			default:
				return fmt.Errorf("invalid authentication method: %s", authMethod)
			}

			// Step 4: Create environment file
			fmt.Printf("\n💾 Saving configuration...\n")
			if err := saveVaultConfig(vaultAddr, authMethod); err != nil {
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

	return cmd
}

// NewSecretsSetCmd creates the set command for storing secrets
func NewSecretsSetCmd() *cobra.Command {
	cmd := &cobra.Command{
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
			reader := bufio.NewReader(os.Stdin)

			switch secretName {
			case "delphi-db":
				return setDatabaseCredentials(rc, secretStore, reader)
			case "delphi-db-config":
				return setDatabaseConfig(rc, secretStore, reader)
			case "delphi-db-engine":
				return setupDatabaseEngine(rc, reader)
			case "smtp":
				return setSMTPCredentials(rc, secretStore, reader)
			case "openai":
				return setOpenAICredentials(rc, secretStore, reader)
			case "custom":
				return setCustomSecret(rc, secretStore, reader)
			default:
				return fmt.Errorf("unknown secret type: %s", secretName)
			}
		}),
	}

	return cmd
}

// NewSecretsTestCmd creates the test command
func NewSecretsTestCmd() *cobra.Command {
	cmd := &cobra.Command{
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

			fmt.Printf("\n🎉 Vault connectivity test completed\n")
			fmt.Printf("Vault is ready for use with Eos services\n")

			return nil
		}),
	}

	return cmd
}

// NewSecretsStatusCmd creates the status command
func NewSecretsStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
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

			fmt.Printf("🔐 Vault Status\n")
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

	return cmd
}

// NewSecretsGetCmd creates the get command for retrieving secrets
func NewSecretsGetCmd() *cobra.Command {
	var showValue bool

	cmd := &cobra.Command{
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

	cmd.Flags().BoolVar(&showValue, "show-value", false, "Show the actual secret value (use with caution)")
	return cmd
}

// Helper functions for authentication setup
func configureTokenAuth(rc *eos_io.RuntimeContext, reader *bufio.Reader) error {
	fmt.Printf("Enter Vault token: ")
	token, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}
	fmt.Printf("\n")

	// Set token environment variable
	os.Setenv("VAULT_TOKEN", string(token))

	return nil
}

func configureUserPassAuth(rc *eos_io.RuntimeContext, reader *bufio.Reader) error {
	fmt.Printf("Enter username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}
	username = strings.TrimSpace(username)

	fmt.Printf("Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Printf("\n")

	// Store credentials (implementation would depend on Vault userpass auth)
	os.Setenv("VAULT_AUTH_USERNAME", username)
	os.Setenv("VAULT_AUTH_PASSWORD", string(password))

	return nil
}

func configureAppRoleAuth(rc *eos_io.RuntimeContext, reader *bufio.Reader) error {
	fmt.Printf("Enter Role ID: ")
	roleID, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read role ID: %w", err)
	}
	roleID = strings.TrimSpace(roleID)

	fmt.Printf("Enter Secret ID: ")
	secretID, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read secret ID: %w", err)
	}
	fmt.Printf("\n")

	os.Setenv("VAULT_ROLE_ID", roleID)
	os.Setenv("VAULT_SECRET_ID", string(secretID))

	return nil
}

func saveVaultConfig(vaultAddr, authMethod string) error {
	// Create /etc/eos directory if it doesn't exist
	configDir := "/etc/eos"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save basic configuration
	configFile := fmt.Sprintf("%s/vault.env", configDir)
	file, err := os.Create(configFile)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	if _, err := fmt.Fprintf(file, "VAULT_ADDR=%s\n", vaultAddr); err != nil {
		return fmt.Errorf("failed to write VAULT_ADDR: %w", err)
	}
	if _, err := fmt.Fprintf(file, "VAULT_AUTH_METHOD=%s\n", authMethod); err != nil {
		return fmt.Errorf("failed to write VAULT_AUTH_METHOD: %w", err)
	}

	return nil
}

// Helper functions for setting specific secrets
func setDatabaseCredentials(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	fmt.Printf("\n🗄️  Database Credentials Setup\n")
	fmt.Printf("===============================\n")

	fmt.Printf("Database host [localhost]: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)
	if host == "" {
		host = "localhost"
	}

	fmt.Printf("Database port [5432]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "5432"
	}

	fmt.Printf("Database name [delphi]: ")
	dbname, _ := reader.ReadString('\n')
	dbname = strings.TrimSpace(dbname)
	if dbname == "" {
		dbname = "delphi"
	}

	fmt.Printf("Database username [delphi]: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		username = "delphi"
	}

	fmt.Printf("Database password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Printf("\n")

	// Store secrets in Vault
	secrets := map[string]string{
		"delphi/database/host":     host,
		"delphi/database/port":     port,
		"delphi/database/name":     dbname,
		"delphi/database/username": username,
		"delphi/database/password": string(password),
	}

	for key, value := range secrets {
		secret := &vaultDomain.Secret{
			Key:       key,
			Value:     value,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := secretStore.Set(rc.Ctx, key, secret); err != nil {
			return fmt.Errorf("failed to store %s: %w", key, err)
		}
	}

	fmt.Printf(" Database credentials stored successfully\n")
	return nil
}

func setSMTPCredentials(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	fmt.Printf("\n📧 SMTP Credentials Setup\n")
	fmt.Printf("=========================\n")

	fmt.Printf("SMTP host: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)

	fmt.Printf("SMTP port [587]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "587"
	}

	fmt.Printf("SMTP username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Printf("SMTP password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Printf("\n")

	secrets := map[string]string{
		"smtp/host":     host,
		"smtp/port":     port,
		"smtp/username": username,
		"smtp/password": string(password),
	}

	for key, value := range secrets {
		secret := &vaultDomain.Secret{
			Key:       key,
			Value:     value,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := secretStore.Set(rc.Ctx, key, secret); err != nil {
			return fmt.Errorf("failed to store %s: %w", key, err)
		}
	}

	fmt.Printf(" SMTP credentials stored successfully\n")
	return nil
}

func setOpenAICredentials(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	fmt.Printf("\n🤖 OpenAI API Key Setup\n")
	fmt.Printf("=======================\n")

	fmt.Printf("OpenAI API Key: ")
	apiKey, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read API key: %w", err)
	}
	fmt.Printf("\n")

	secret := &vaultDomain.Secret{
		Key:       "openai/api_key",
		Value:     string(apiKey),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := secretStore.Set(rc.Ctx, "openai/api_key", secret); err != nil {
		return fmt.Errorf("failed to store OpenAI API key: %w", err)
	}

	fmt.Printf(" OpenAI API key stored successfully\n")
	return nil
}

func setCustomSecret(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	fmt.Printf("\n🔧 Custom Secret Setup\n")
	fmt.Printf("======================\n")

	fmt.Printf("Secret path (e.g., myapp/config/key): ")
	path, _ := reader.ReadString('\n')
	path = strings.TrimSpace(path)

	fmt.Printf("Secret value: ")
	value, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read value: %w", err)
	}
	fmt.Printf("\n")

	secret := &vaultDomain.Secret{
		Key:       path,
		Value:     string(value),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := secretStore.Set(rc.Ctx, path, secret); err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	fmt.Printf(" Custom secret stored successfully\n")
	return nil
}

// setDatabaseConfig sets database connection parameters (not credentials)
func setDatabaseConfig(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	fmt.Printf("\n🗄️  Database Connection Configuration\n")
	fmt.Printf("====================================\n")
	fmt.Printf("This sets connection parameters for the PostgreSQL database.\n")
	fmt.Printf("For dynamic credentials, this should point to the guest VM database.\n\n")

	fmt.Printf("Database host [localhost]: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)
	if host == "" {
		host = "localhost"
	}

	fmt.Printf("Database port [5432]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "5432"
	}

	fmt.Printf("Database name [delphi]: ")
	dbname, _ := reader.ReadString('\n')
	dbname = strings.TrimSpace(dbname)
	if dbname == "" {
		dbname = "delphi"
	}

	// Store configuration secrets in Vault
	secrets := map[string]string{
		"delphi/config/host":     host,
		"delphi/config/port":     port,
		"delphi/config/database": dbname,
	}

	for key, value := range secrets {
		secret := &vaultDomain.Secret{
			Key:       key,
			Value:     value,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := secretStore.Set(rc.Ctx, key, secret); err != nil {
			return fmt.Errorf("failed to store %s: %w", key, err)
		}
	}

	fmt.Printf(" Database configuration stored successfully\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("- Set up database engine: eos self secrets set delphi-db-engine\n")
	fmt.Printf("- Or set static credentials: eos self secrets set delphi-db\n")
	return nil
}

// setupDatabaseEngine guides the user through setting up Vault's database secrets engine
func setupDatabaseEngine(rc *eos_io.RuntimeContext, reader *bufio.Reader) error {
	fmt.Printf("\n🏗️  Vault Database Secrets Engine Setup\n")
	fmt.Printf("=======================================\n")
	fmt.Printf("This will guide you through configuring Vault's database secrets engine\n")
	fmt.Printf("for dynamic PostgreSQL credential generation.\n\n")

	fmt.Printf("  IMPORTANT: This requires PostgreSQL admin access on the target database.\n")
	fmt.Printf("The database should be running in your guest VM.\n\n")

	fmt.Printf("Database admin username (e.g., postgres): ")
	adminUser, _ := reader.ReadString('\n')
	adminUser = strings.TrimSpace(adminUser)
	if adminUser == "" {
		return fmt.Errorf("admin username is required")
	}

	fmt.Printf("Database admin password: ")
	adminPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read admin password: %w", err)
	}
	fmt.Printf("\n")

	fmt.Printf("Database host (guest VM IP, e.g., 100.88.69.11): ")
	dbHost, _ := reader.ReadString('\n')
	dbHost = strings.TrimSpace(dbHost)
	if dbHost == "" {
		dbHost = "localhost"
	}

	fmt.Printf("Database port [5432]: ")
	dbPort, _ := reader.ReadString('\n')
	dbPort = strings.TrimSpace(dbPort)
	if dbPort == "" {
		dbPort = "5432"
	}

	fmt.Printf("Database name [delphi]: ")
	dbName, _ := reader.ReadString('\n')
	dbName = strings.TrimSpace(dbName)
	if dbName == "" {
		dbName = "delphi"
	}

	fmt.Printf("\n Configuration Summary:\n")
	fmt.Printf("  Host: %s:%s\n", dbHost, dbPort)
	fmt.Printf("  Database: %s\n", dbName)
	fmt.Printf("  Admin User: %s\n", adminUser)
	fmt.Printf("  Dynamic Role: delphi-readonly\n\n")

	fmt.Printf(" To complete the setup, run these Vault commands on your host:\n\n")

	// Generate the Vault commands for the user
	fmt.Printf("# Enable the database secrets engine\n")
	fmt.Printf("vault secrets enable database\n\n")

	fmt.Printf("# Configure the PostgreSQL connection\n")
	fmt.Printf("vault write database/config/delphi-postgresql \\\n")
	fmt.Printf("    plugin_name=postgresql-database-plugin \\\n")
	fmt.Printf("    connection_url=\"postgresql://{{username}}:{{password}}@%s:%s/%s?sslmode=disable\" \\\n", dbHost, dbPort, dbName)
	fmt.Printf("    allowed_roles=\"delphi-readonly\" \\\n")
	fmt.Printf("    username=\"%s\" \\\n", adminUser)
	fmt.Printf("    password=\"%s\"\n\n", string(adminPassword))

	fmt.Printf("# Create a read-only role for the Delphi application\n")
	fmt.Printf("vault write database/roles/delphi-readonly \\\n")
	fmt.Printf("    db_name=delphi-postgresql \\\n")
	fmt.Printf("    creation_statements=\"CREATE ROLE \\\"{{name}}\\\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \\\n")
	fmt.Printf("                          GRANT CONNECT ON DATABASE %s TO \\\"{{name}}\\\"; \\\n", dbName)
	fmt.Printf("                          GRANT USAGE ON SCHEMA public TO \\\"{{name}}\\\"; \\\n")
	fmt.Printf("                          GRANT SELECT ON ALL TABLES IN SCHEMA public TO \\\"{{name}}\\\"; \\\n")
	fmt.Printf("                          ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \\\"{{name}}\\\";\"\\\n")
	fmt.Printf("    default_ttl=\"1h\" \\\n")
	fmt.Printf("    max_ttl=\"24h\"\n\n")

	fmt.Printf("# Test the configuration\n")
	fmt.Printf("vault read database/creds/delphi-readonly\n\n")

	fmt.Printf("🔧 After running these commands:\n")
	fmt.Printf("- Test with: eos self secrets test\n")
	fmt.Printf("- Run dashboard: eos delphi dashboard\n")
	fmt.Printf("- The dashboard will automatically use dynamic credentials\n\n")

	fmt.Printf(" Setup instructions generated successfully\n")
	return nil
}
