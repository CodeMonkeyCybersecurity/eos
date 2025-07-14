package read

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var databaseStatusCmd = &cobra.Command{
	Use:     "database-status",
	Aliases: []string{"database-stat", "db-status", "db-stat"},
	Short:   "Get database status information",
	Long: `Get comprehensive status information about a database.

This command provides detailed database status including:
- Database version and type
- Connection status and count
- Database size and usage
- Performance metrics
- Uptime information

Examples:
  eos read database-status --host localhost --database delphi
  eos read database-status --json                           # JSON output
  eos read database-status --host 192.168.1.100 --username myuser`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		host, _ := cmd.Flags().GetString("host")
		port, _ := cmd.Flags().GetInt("port")
		database, _ := cmd.Flags().GetString("database")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		sslMode, _ := cmd.Flags().GetString("ssl-mode")
		outputJSON, _ := cmd.Flags().GetBool("json")

		logger.Info("Getting database status",
			zap.String("host", host),
			zap.String("database", database))

		// Build database configuration
		config := &database_management.DatabaseConfig{
			Type:     database_management.DatabaseTypePostgreSQL,
			Host:     host,
			Port:     port,
			Database: database,
			Username: username,
			Password: password,
			SSLMode:  sslMode,
		}

		// Set defaults
		if config.Host == "" {
			config.Host = "localhost"
		}
		if config.Port == 0 {
			config.Port = 5432
		}
		if config.Username == "" {
			config.Username = "postgres"
		}
		if config.SSLMode == "" {
			config.SSLMode = "disable"
		}

		// Get database status
		status, err := database_management.GetDatabaseStatus(rc, config)
		if err != nil {
			return fmt.Errorf("failed to get database status: %w", err)
		}

		if outputJSON {
			return outputJSONDatabaseStatus(rc, status)
		}

		return outputTableDatabaseStatus(rc, status)
	}),
}

func init() {
	databaseStatusCmd.Flags().String("host", "localhost", "Database host")
	databaseStatusCmd.Flags().Int("port", 5432, "Database port")
	databaseStatusCmd.Flags().String("database", "postgres", "Database name")
	databaseStatusCmd.Flags().String("username", "postgres", "Database username")
	databaseStatusCmd.Flags().String("password", "", "Database password")
	databaseStatusCmd.Flags().String("ssl-mode", "disable", "SSL mode (disable, require, verify-ca, verify-full)")
	databaseStatusCmd.Flags().Bool("json", false, "Output in JSON format")

	// Register with parent command
	ReadCmd.AddCommand(databaseStatusCmd)
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputJSONDatabaseStatus(rc *eos_io.RuntimeContext, status *database_management.DatabaseStatus) error {
	logger := otelzap.Ctx(rc.Ctx)
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	logger.Info("terminal prompt: JSON output", zap.String("data", string(data)))
	return nil
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputTableDatabaseStatus(rc *eos_io.RuntimeContext, status *database_management.DatabaseStatus) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: Database Status")
	logger.Info("terminal prompt: ===============")

	logger.Info("terminal prompt: Type", zap.String("value", string(status.Type)))
	logger.Info("terminal prompt: Version", zap.String("value", status.Version))
	logger.Info("terminal prompt: Status", zap.String("value", status.Status))

	if status.Uptime > 0 {
		logger.Info("terminal prompt: Uptime", zap.String("value", status.Uptime.String()))
	}

	logger.Info("terminal prompt: Connections", zap.String("value", fmt.Sprintf("%d/%d", status.Connections, status.MaxConnections)))

	if status.DatabaseSize != "" {
		logger.Info("terminal prompt: Database Size", zap.String("value", status.DatabaseSize))
	}

	if status.Memory != "" {
		logger.Info("terminal prompt: Memory Usage", zap.String("value", status.Memory))
	}

	if status.CPU > 0 {
		logger.Info("terminal prompt: CPU Usage", zap.String("value", fmt.Sprintf("%.2f%%", status.CPU)))
	}

	return nil
}
