package create

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
			return database_management.RunInteractiveVaultSetup(rc, manager)
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
	databaseVaultPostgresCmd.Flags().Int("port", shared.PortPostgreSQL, "Database port")
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
