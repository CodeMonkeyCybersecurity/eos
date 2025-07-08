package create

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var databaseVaultPostgresCmd = &cobra.Command{
	Use:     "database-vault-postgres",
	Aliases: []string{"database-vault-postgresql", "vault-postgres", "vault-postgresql"},
	Short:   "Setup Vault dynamic PostgreSQL credentials",
	Long: `Setup Vault dynamic PostgreSQL credentials for secure database access.

This command provides comprehensive Vault database integration:
- Enable and configure Vault database secrets engine
- Configure PostgreSQL connection parameters
- Create read-only database roles with TTL
- Test dynamic credential generation
- Integration with Eos secret management

Examples:
  eos create database-vault-postgres --interactive                    # Interactive setup
  eos create database-vault-postgres --host localhost --database delphi
  eos create database-vault-postgres --host 192.168.1.100 --admin-username postgres
  eos create database-vault-postgres --connection-name myapp-db --test`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		host, _ := cmd.Flags().GetString("host")
		port, _ := cmd.Flags().GetInt("port")
		database, _ := cmd.Flags().GetString("database")
		adminUsername, _ := cmd.Flags().GetString("admin-username")
		adminPassword, _ := cmd.Flags().GetString("admin-password")
		connectionName, _ := cmd.Flags().GetString("connection-name")
		engineMount, _ := cmd.Flags().GetString("engine-mount")
		interactive, _ := cmd.Flags().GetBool("interactive")
		testConnection, _ := cmd.Flags().GetBool("test")
		force, _ := cmd.Flags().GetBool("force")

		logger.Info("Setting up Vault dynamic PostgreSQL credentials",
			zap.String("host", host),
			zap.Int("port", port),
			zap.String("database", database),
			zap.Bool("interactive", interactive))

		manager := database_management.NewDatabaseManager()

		// Interactive mode
		if interactive {
			return runInteractiveVaultSetup(rc, manager)
		}

		// Build configuration
		options := &database_management.VaultSetupOptions{
			DatabaseConfig: &database_management.DatabaseConfig{
				Type:     database_management.DatabaseTypePostgreSQL,
				Host:     host,
				Port:     port,
				Database: database,
				SSLMode:  "disable",
			},
			AdminUsername:  adminUsername,
			AdminPassword:  adminPassword,
			ConnectionName: connectionName,
			EngineMount:    engineMount,
			TestConnection: testConnection,
			Interactive:    interactive,
			Force:          force,
		}

		// Set defaults
		if options.DatabaseConfig.Host == "" {
			options.DatabaseConfig.Host = "localhost"
		}
		if options.DatabaseConfig.Port == 0 {
			options.DatabaseConfig.Port = 5432
		}
		if options.DatabaseConfig.Database == "" {
			options.DatabaseConfig.Database = "delphi"
		}
		if options.AdminUsername == "" {
			options.AdminUsername = "postgres"
		}
		if options.ConnectionName == "" {
			options.ConnectionName = "delphi-postgresql"
		}
		if options.EngineMount == "" {
			options.EngineMount = "database"
		}

		// Create default roles
		options.Roles = []*database_management.Role{
			{
				Name:   "delphi-readonly",
				DBName: options.ConnectionName,
				CreationStatements: []string{
					`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'`,
					fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO "{{name}}"`, options.DatabaseConfig.Database),
					`GRANT USAGE ON SCHEMA public TO "{{name}}"`,
					`GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}"`,
					`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "{{name}}"`,
				},
				DefaultTTL: time.Hour,
				MaxTTL:     24 * time.Hour,
			},
		}

		// Validate required fields
		if options.AdminPassword == "" {
			return fmt.Errorf("admin password is required (use --admin-password or --interactive)")
		}

		return manager.SetupVaultPostgreSQL(rc, options)
	}),
}

func init() {
	databaseVaultPostgresCmd.Flags().String("host", "localhost", "Database host")
	databaseVaultPostgresCmd.Flags().Int("port", 5432, "Database port")
	databaseVaultPostgresCmd.Flags().String("database", "delphi", "Database name")
	databaseVaultPostgresCmd.Flags().String("admin-username", "postgres", "Database admin username")
	databaseVaultPostgresCmd.Flags().String("admin-password", "", "Database admin password")
	databaseVaultPostgresCmd.Flags().String("connection-name", "delphi-postgresql", "Vault connection name")
	databaseVaultPostgresCmd.Flags().String("engine-mount", "database", "Vault database engine mount point")
	databaseVaultPostgresCmd.Flags().BoolP("interactive", "i", false, "Interactive setup mode")
	databaseVaultPostgresCmd.Flags().Bool("test", true, "Test credential generation after setup")
	databaseVaultPostgresCmd.Flags().BoolP("force", "f", false, "Force setup without confirmation")

	// Register with parent command
	CreateCmd.AddCommand(databaseVaultPostgresCmd)
}

// Helper function for interactive setup
func runInteractiveVaultSetup(rc *eos_io.RuntimeContext, manager *database_management.DatabaseManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Printf("🔐 Vault Dynamic PostgreSQL Credentials Setup\n")
	fmt.Printf("==============================================\n\n")

	options := &database_management.VaultSetupOptions{
		DatabaseConfig: &database_management.DatabaseConfig{
			Type: database_management.DatabaseTypePostgreSQL,
		},
		Interactive: true,
	}

	// Database configuration
	fmt.Printf("Database Configuration\n")
	fmt.Printf("----------------------\n")

	fmt.Print("Database host [localhost]: ")
	var host string
	if _, err := fmt.Scanln(&host); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read host input", zap.Error(err))
		return fmt.Errorf("failed to read host: %w", err)
	}
	if host == "" {
		host = "localhost"
	}
	options.DatabaseConfig.Host = host

	fmt.Print("Database port [5432]: ")
	var portStr string
	if _, err := fmt.Scanln(&portStr); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read port input", zap.Error(err))
		return fmt.Errorf("failed to read port: %w", err)
	}
	if portStr == "" {
		options.DatabaseConfig.Port = 5432
	} else {
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			logger.Warn("Failed to parse port", zap.Error(err))
			return fmt.Errorf("invalid port number: %w", err)
		}
		options.DatabaseConfig.Port = port
	}

	fmt.Print("Database name [delphi]: ")
	var database string
	if _, err := fmt.Scanln(&database); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read database input", zap.Error(err))
		return fmt.Errorf("failed to read database: %w", err)
	}
	if database == "" {
		database = "delphi"
	}
	options.DatabaseConfig.Database = database

	fmt.Print("SSL mode [disable]: ")
	var sslMode string
	if _, err := fmt.Scanln(&sslMode); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read SSL mode input", zap.Error(err))
		return fmt.Errorf("failed to read SSL mode: %w", err)
	}
	if sslMode == "" {
		sslMode = "disable"
	}
	options.DatabaseConfig.SSLMode = sslMode

	fmt.Printf("\nAdmin Credentials\n")
	fmt.Printf("-----------------\n")

	fmt.Print("Admin username [postgres]: ")
	var adminUsername string
	if _, err := fmt.Scanln(&adminUsername); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read admin username input", zap.Error(err))
		return fmt.Errorf("failed to read admin username: %w", err)
	}
	if adminUsername == "" {
		adminUsername = "postgres"
	}
	options.AdminUsername = adminUsername

	fmt.Print("Admin password: ")
	var adminPassword string
	if _, err := fmt.Scanln(&adminPassword); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read admin password input", zap.Error(err))
		return fmt.Errorf("failed to read admin password: %w", err)
	}
	if adminPassword == "" {
		return fmt.Errorf("admin password is required")
	}
	options.AdminPassword = adminPassword

	fmt.Printf("\nVault Configuration\n")
	fmt.Printf("-------------------\n")

	fmt.Print("Connection name [delphi-postgresql]: ")
	var connectionName string
	if _, err := fmt.Scanln(&connectionName); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read connection name input", zap.Error(err))
		return fmt.Errorf("failed to read connection name: %w", err)
	}
	if connectionName == "" {
		connectionName = "delphi-postgresql"
	}
	options.ConnectionName = connectionName

	fmt.Print("Engine mount point [database]: ")
	var engineMount string
	if _, err := fmt.Scanln(&engineMount); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read engine mount input", zap.Error(err))
		return fmt.Errorf("failed to read engine mount: %w", err)
	}
	if engineMount == "" {
		engineMount = "database"
	}
	options.EngineMount = engineMount

	fmt.Print("Test connection after setup? [Y/n]: ")
	var testResponse string
	if _, err := fmt.Scanln(&testResponse); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read test response input", zap.Error(err))
		return fmt.Errorf("failed to read test response: %w", err)
	}
	options.TestConnection = testResponse != "n" && testResponse != "N"

	// Create default roles
	options.Roles = []*database_management.Role{
		{
			Name:   "delphi-readonly",
			DBName: connectionName,
			CreationStatements: []string{
				`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'`,
				fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO "{{name}}"`, database),
				`GRANT USAGE ON SCHEMA public TO "{{name}}"`,
				`GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}"`,
				`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "{{name}}"`,
			},
			DefaultTTL: time.Hour,
			MaxTTL:     24 * time.Hour,
		},
	}

	fmt.Printf("\nConfiguration Summary:\n")
	fmt.Printf("  Host: %s:%d\n", options.DatabaseConfig.Host, options.DatabaseConfig.Port)
	fmt.Printf("  Database: %s\n", options.DatabaseConfig.Database)
	fmt.Printf("  Admin User: %s\n", options.AdminUsername)
	fmt.Printf("  Connection: %s\n", options.ConnectionName)
	fmt.Printf("  Engine Mount: %s\n", options.EngineMount)
	fmt.Printf("  Test Connection: %t\n", options.TestConnection)
	fmt.Printf("\n")

	fmt.Print("Proceed with setup? [Y/n]: ")
	var confirmResponse string
	if _, err := fmt.Scanln(&confirmResponse); err != nil && err.Error() != "unexpected newline" {
		logger.Warn("Failed to read confirmation input", zap.Error(err))
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	if confirmResponse == "n" || confirmResponse == "N" {
		logger.Info("Setup cancelled by user")
		return nil
	}

	return manager.SetupVaultPostgreSQL(rc, options)
}