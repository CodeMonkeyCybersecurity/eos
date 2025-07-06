package database

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

// newVaultPostgresCmd creates the Vault PostgreSQL setup command
func newVaultPostgresCmd() *cobra.Command {
	var (
		host           string
		port           int
		database       string
		adminUsername  string
		adminPassword  string
		connectionName string
		engineMount    string
		interactive    bool
		testConnection bool
		force          bool
	)

	cmd := &cobra.Command{
		Use:     "vault-postgres",
		Aliases: []string{"vault-postgresql", "setup-vault-postgres"},
		Short:   "Setup Vault dynamic PostgreSQL credentials",
		Long: `Setup Vault dynamic PostgreSQL credentials for secure database access.

This command provides comprehensive Vault database integration:
- Enable and configure Vault database secrets engine
- Configure PostgreSQL connection parameters
- Create read-only database roles with TTL
- Test dynamic credential generation
- Integration with Eos secret management

Examples:
  eos database vault-postgres --interactive                    # Interactive setup
  eos database vault-postgres --host localhost --database delphi
  eos database vault-postgres --host 192.168.1.100 --admin-username postgres
  eos database vault-postgres --connection-name myapp-db --test`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

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

	cmd.Flags().StringVar(&host, "host", "localhost", "Database host")
	cmd.Flags().IntVar(&port, "port", 5432, "Database port")
	cmd.Flags().StringVar(&database, "database", "delphi", "Database name")
	cmd.Flags().StringVar(&adminUsername, "admin-username", "postgres", "Database admin username")
	cmd.Flags().StringVar(&adminPassword, "admin-password", "", "Database admin password")
	cmd.Flags().StringVar(&connectionName, "connection-name", "delphi-postgresql", "Vault connection name")
	cmd.Flags().StringVar(&engineMount, "engine-mount", "database", "Vault database engine mount point")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive setup mode")
	cmd.Flags().BoolVar(&testConnection, "test", true, "Test credential generation after setup")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force setup without confirmation")

	return cmd
}

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
	fmt.Scanln(&host)
	if host == "" {
		host = "localhost"
	}
	options.DatabaseConfig.Host = host

	fmt.Print("Database port [5432]: ")
	var portStr string
	fmt.Scanln(&portStr)
	if portStr == "" {
		options.DatabaseConfig.Port = 5432
	} else {
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		options.DatabaseConfig.Port = port
	}

	fmt.Print("Database name [delphi]: ")
	var database string
	fmt.Scanln(&database)
	if database == "" {
		database = "delphi"
	}
	options.DatabaseConfig.Database = database

	fmt.Print("SSL mode [disable]: ")
	var sslMode string
	fmt.Scanln(&sslMode)
	if sslMode == "" {
		sslMode = "disable"
	}
	options.DatabaseConfig.SSLMode = sslMode

	fmt.Printf("\nAdmin Credentials\n")
	fmt.Printf("-----------------\n")

	fmt.Print("Admin username [postgres]: ")
	var adminUsername string
	fmt.Scanln(&adminUsername)
	if adminUsername == "" {
		adminUsername = "postgres"
	}
	options.AdminUsername = adminUsername

	fmt.Print("Admin password: ")
	var adminPassword string
	fmt.Scanln(&adminPassword)
	if adminPassword == "" {
		return fmt.Errorf("admin password is required")
	}
	options.AdminPassword = adminPassword

	fmt.Printf("\nVault Configuration\n")
	fmt.Printf("-------------------\n")

	fmt.Print("Connection name [delphi-postgresql]: ")
	var connectionName string
	fmt.Scanln(&connectionName)
	if connectionName == "" {
		connectionName = "delphi-postgresql"
	}
	options.ConnectionName = connectionName

	fmt.Print("Engine mount point [database]: ")
	var engineMount string
	fmt.Scanln(&engineMount)
	if engineMount == "" {
		engineMount = "database"
	}
	options.EngineMount = engineMount

	fmt.Print("Test connection after setup? [Y/n]: ")
	var testResponse string
	fmt.Scanln(&testResponse)
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
	fmt.Scanln(&confirmResponse)
	if confirmResponse == "n" || confirmResponse == "N" {
		logger.Info("Setup cancelled by user")
		return nil
	}

	return manager.SetupVaultPostgreSQL(rc, options)
}
