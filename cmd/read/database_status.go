package read

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
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

		manager := database_management.NewDatabaseManager()

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
		status, err := manager.GetDatabaseStatus(rc, config)
		if err != nil {
			return fmt.Errorf("failed to get database status: %w", err)
		}

		if outputJSON {
			return outputJSONDatabaseStatus(status)
		}

		return outputTableDatabaseStatus(status)
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

func outputJSONDatabaseStatus(status *database_management.DatabaseStatus) error {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputTableDatabaseStatus(status *database_management.DatabaseStatus) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Printf("Database Status\n")
	fmt.Printf("===============\n\n")

	fmt.Fprintf(w, "Type:\t%s\n", status.Type)
	fmt.Fprintf(w, "Version:\t%s\n", status.Version)
	fmt.Fprintf(w, "Status:\t%s\n", status.Status)
	
	if status.Uptime > 0 {
		fmt.Fprintf(w, "Uptime:\t%s\n", status.Uptime.String())
	}
	
	fmt.Fprintf(w, "Connections:\t%d/%d\n", status.Connections, status.MaxConnections)
	
	if status.DatabaseSize != "" {
		fmt.Fprintf(w, "Database Size:\t%s\n", status.DatabaseSize)
	}
	
	if status.Memory != "" {
		fmt.Fprintf(w, "Memory Usage:\t%s\n", status.Memory)
	}
	
	if status.CPU > 0 {
		fmt.Fprintf(w, "CPU Usage:\t%.2f%%\n", status.CPU)
	}

	return nil
}