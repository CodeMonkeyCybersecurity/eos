package database

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

// newStatusCmd creates the database status command
func newStatusCmd() *cobra.Command {
	var (
		host       string
		port       int
		database   string
		username   string
		password   string
		sslMode    string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:     "status",
		Aliases: []string{"stat"},
		Short:   "Get database status information",
		Long: `Get comprehensive status information about a database.

This command provides detailed database status including:
- Database version and type
- Connection status and count
- Database size and usage
- Performance metrics
- Uptime information

Examples:
  eos database status --host localhost --database delphi
  eos database status --json                           # JSON output
  eos database status --host 192.168.1.100 --username myuser`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

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

	cmd.Flags().StringVar(&host, "host", "localhost", "Database host")
	cmd.Flags().IntVar(&port, "port", 5432, "Database port")
	cmd.Flags().StringVar(&database, "database", "postgres", "Database name")
	cmd.Flags().StringVar(&username, "username", "postgres", "Database username")
	cmd.Flags().StringVar(&password, "password", "", "Database password")
	cmd.Flags().StringVar(&sslMode, "ssl-mode", "disable", "SSL mode (disable, require, verify-ca, verify-full)")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
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