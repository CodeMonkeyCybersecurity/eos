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

// newQueryCmd creates the database query command
func newQueryCmd() *cobra.Command {
	var (
		host        string
		port        int
		database    string
		username    string
		password    string
		sslMode     string
		sql         string
		file        string
		transaction bool
		dryRun      bool
		outputJSON  bool
	)

	cmd := &cobra.Command{
		Use:     "query",
		Aliases: []string{"exec", "execute"},
		Short:   "Execute database queries",
		Long: `Execute SQL queries against a database.

This command provides query execution functionality:
- Execute SQL queries from command line or file
- Transaction support
- Dry-run mode for testing
- JSON output for automation
- Parameter substitution

Examples:
  eos database query --sql "SELECT * FROM users"
  eos database query --file query.sql --transaction
  eos database query --sql "SELECT count(*) FROM logs" --json
  eos database query --sql "DELETE FROM temp_table" --dry-run`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if sql == "" && file == "" {
				return fmt.Errorf("either --sql or --file is required")
			}

			if sql != "" && file != "" {
				return fmt.Errorf("cannot specify both --sql and --file")
			}

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

			// Read SQL from file if specified
			if file != "" {
				content, err := os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("failed to read SQL file: %w", err)
				}
				sql = string(content)
			}

			// Build operation
			operation := &database_management.DatabaseOperation{
				Type:        "query",
				Database:    database,
				Query:       sql,
				Transaction: transaction,
				DryRun:      dryRun,
			}

			logger.Info("Executing database query",
				zap.String("database", database),
				zap.Bool("transaction", transaction),
				zap.Bool("dry_run", dryRun))

			result, err := manager.ExecuteQuery(rc, config, operation)
			if err != nil {
				return fmt.Errorf("query execution failed: %w", err)
			}

			if outputJSON {
				return outputJSONQueryResult(result)
			}

			return outputTableQueryResult(result)
		}),
	}

	cmd.Flags().StringVar(&host, "host", "localhost", "Database host")
	cmd.Flags().IntVar(&port, "port", 5432, "Database port")
	cmd.Flags().StringVar(&database, "database", "postgres", "Database name")
	cmd.Flags().StringVar(&username, "username", "postgres", "Database username")
	cmd.Flags().StringVar(&password, "password", "", "Database password")
	cmd.Flags().StringVar(&sslMode, "ssl-mode", "disable", "SSL mode")
	cmd.Flags().StringVar(&sql, "sql", "", "SQL query to execute")
	cmd.Flags().StringVar(&file, "file", "", "SQL file to execute")
	cmd.Flags().BoolVar(&transaction, "transaction", false, "Execute in transaction")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Simulate query execution")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

func outputJSONQueryResult(result *database_management.DatabaseOperationResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputTableQueryResult(result *database_management.DatabaseOperationResult) error {
	fmt.Printf("Query Result\n")
	fmt.Printf("============\n\n")

	fmt.Printf("Success: %t\n", result.Success)
	fmt.Printf("Message: %s\n", result.Message)
	fmt.Printf("Duration: %s\n", result.Duration.String())
	
	if result.RowsAffected > 0 {
		fmt.Printf("Rows Affected: %d\n", result.RowsAffected)
	}

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
	}

	if len(result.Data) > 0 {
		fmt.Printf("\nData (%d rows):\n", len(result.Data))
		
		if len(result.Data) > 0 {
			// Create table writer
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			defer func() {
				if err := w.Flush(); err != nil {
					// Best effort - log but don't fail
					fmt.Fprintf(os.Stderr, "Warning: failed to flush output: %v\n", err)
				}
			}()

			// Get column names from first row
			var columns []string
			for col := range result.Data[0] {
				columns = append(columns, col)
			}

			// Print header
			for i, col := range columns {
				if i > 0 {
					if _, err := fmt.Fprint(w, "\t"); err != nil {
						return fmt.Errorf("failed to write tab: %w", err)
					}
				}
				if _, err := fmt.Fprint(w, col); err != nil {
					return fmt.Errorf("failed to write column header: %w", err)
				}
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return fmt.Errorf("failed to write newline: %w", err)
			}

			// Print separator
			for i := range columns {
				if i > 0 {
					if _, err := fmt.Fprint(w, "\t"); err != nil {
						return fmt.Errorf("failed to write separator tab: %w", err)
					}
				}
				if _, err := fmt.Fprint(w, "---"); err != nil {
					return fmt.Errorf("failed to write separator: %w", err)
				}
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return fmt.Errorf("failed to write separator newline: %w", err)
			}

			// Print data rows (limit to first 50 for readability)
			maxRows := len(result.Data)
			if maxRows > 50 {
				maxRows = 50
			}

			for i := 0; i < maxRows; i++ {
				row := result.Data[i]
				for j, col := range columns {
					if j > 0 {
						if _, err := fmt.Fprint(w, "\t"); err != nil {
							return fmt.Errorf("failed to write data tab: %w", err)
						}
					}
					if val, ok := row[col]; ok && val != nil {
						if _, err := fmt.Fprintf(w, "%v", val); err != nil {
							return fmt.Errorf("failed to write value: %w", err)
						}
					} else {
						if _, err := fmt.Fprint(w, "NULL"); err != nil {
							return fmt.Errorf("failed to write NULL: %w", err)
						}
					}
				}
				if _, err := fmt.Fprintln(w); err != nil {
					return fmt.Errorf("failed to write row newline: %w", err)
				}
			}

			if len(result.Data) > 50 {
				fmt.Printf("\n... and %d more rows (use --json for complete output)\n", len(result.Data)-50)
			}
		}
	}

	return nil
}