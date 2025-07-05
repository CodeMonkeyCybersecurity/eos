// cmd/database/database.go
package database

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// DatabaseCmd is the root command for database operations
var DatabaseCmd = &cobra.Command{
	Use:   "database",
	Short: "Database management and operations",
	Long: `Comprehensive database management and operations tools.

This command provides enhanced database functionality including:
- Vault dynamic credential management
- PostgreSQL operations and monitoring
- Schema inspection and management
- Health checks and status monitoring
- Migration support

Examples:
  eos database status --config config.json     # Get database status
  eos database vault-postgres --interactive    # Setup Vault PostgreSQL
  eos database query --sql "SELECT * FROM users" # Execute query
  eos database schema --database mydb          # Inspect schema
  eos database health-check --database mydb    # Health check`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for database command")
		_ = cmd.Help()
		return nil
	}),
}

func init() {
	// Add subcommands
	DatabaseCmd.AddCommand(newVaultPostgresCmd())
	DatabaseCmd.AddCommand(newStatusCmd())
	DatabaseCmd.AddCommand(newQueryCmd())
	DatabaseCmd.AddCommand(newSchemaCmd())
	DatabaseCmd.AddCommand(newHealthCheckCmd())
	DatabaseCmd.AddCommand(newCredentialsCmd())
}