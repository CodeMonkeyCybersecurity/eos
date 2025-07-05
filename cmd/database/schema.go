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

// newSchemaCmd creates the database schema inspection command
func newSchemaCmd() *cobra.Command {
	var (
		host       string
		port       int
		database   string
		username   string
		password   string
		sslMode    string
		outputJSON bool
		detailed   bool
		tableName  string
	)

	cmd := &cobra.Command{
		Use:     "schema",
		Aliases: []string{"inspect"},
		Short:   "Inspect database schema",
		Long: `Inspect and analyze database schema information.

This command provides comprehensive schema inspection:
- List all tables and their structures
- Column information with types and constraints
- View and index information
- Trigger definitions
- Foreign key relationships

Examples:
  eos database schema --database mydb                    # Full schema
  eos database schema --table users --detailed           # Specific table
  eos database schema --json                             # JSON output
  eos database schema --host 192.168.1.100 --database delphi`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			logger.Info("Inspecting database schema",
				zap.String("database", database),
				zap.String("table", tableName))

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

			// Get schema information
			schemaInfo, err := manager.GetSchemaInfo(rc, config)
			if err != nil {
				return fmt.Errorf("failed to get schema information: %w", err)
			}

			// Filter by table name if specified
			if tableName != "" {
				filteredTables := make([]database_management.TableInfo, 0)
				for _, table := range schemaInfo.Tables {
					if table.Name == tableName {
						filteredTables = append(filteredTables, table)
						break
					}
				}
				schemaInfo.Tables = filteredTables
				
				if len(filteredTables) == 0 {
					return fmt.Errorf("table '%s' not found", tableName)
				}
			}

			if outputJSON {
				return outputJSONSchema(schemaInfo)
			}

			return outputTableSchema(schemaInfo, detailed)
		}),
	}

	cmd.Flags().StringVar(&host, "host", "localhost", "Database host")
	cmd.Flags().IntVar(&port, "port", 5432, "Database port")
	cmd.Flags().StringVar(&database, "database", "postgres", "Database name")
	cmd.Flags().StringVar(&username, "username", "postgres", "Database username")
	cmd.Flags().StringVar(&password, "password", "", "Database password")
	cmd.Flags().StringVar(&sslMode, "ssl-mode", "disable", "SSL mode")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Show detailed information")
	cmd.Flags().StringVarP(&tableName, "table", "t", "", "Inspect specific table")

	return cmd
}

func outputJSONSchema(schemaInfo *database_management.SchemaInfo) error {
	data, err := json.MarshalIndent(schemaInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputTableSchema(schemaInfo *database_management.SchemaInfo, detailed bool) error {
	fmt.Printf("Database Schema: %s\n", schemaInfo.Database)
	fmt.Printf("=================\n\n")

	if len(schemaInfo.Tables) == 0 {
		fmt.Println("No tables found.")
		return nil
	}

	fmt.Printf("Tables (%d):\n", len(schemaInfo.Tables))

	for _, table := range schemaInfo.Tables {
		fmt.Printf("\n📋 Table: %s.%s\n", table.Schema, table.Name)
		
		if table.RowCount > 0 {
			fmt.Printf("   Rows: %d", table.RowCount)
		}
		if table.Size != "" {
			fmt.Printf("   Size: %s", table.Size)
		}
		if table.RowCount > 0 || table.Size != "" {
			fmt.Printf("\n")
		}

		if len(table.Columns) > 0 {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "   Column\tType\tNullable\tDefault\tConstraints\n")
			fmt.Fprintf(w, "   ------\t----\t--------\t-------\t-----------\n")

			for _, column := range table.Columns {
				constraints := ""
				if column.IsPrimaryKey {
					constraints += "PK "
				}
				if column.IsForeignKey {
					constraints += "FK "
				}

				nullable := "NO"
				if column.Nullable {
					nullable = "YES"
				}

				defaultValue := column.DefaultValue
				if defaultValue == "" {
					defaultValue = "-"
				}

				fmt.Fprintf(w, "   %s\t%s\t%s\t%s\t%s\n",
					column.Name, column.Type, nullable, defaultValue, constraints)
			}
			w.Flush()
		}

		if !detailed && len(table.Columns) > 10 {
			fmt.Printf("   ... and %d more columns (use --detailed to see all)\n", len(table.Columns)-10)
		}
	}

	// Show views if any
	if len(schemaInfo.Views) > 0 {
		fmt.Printf("\nViews (%d):\n", len(schemaInfo.Views))
		for _, view := range schemaInfo.Views {
			fmt.Printf("  📄 %s.%s\n", view.Schema, view.Name)
			if detailed && view.Definition != "" {
				fmt.Printf("     Definition: %s\n", view.Definition)
			}
		}
	}

	// Show indexes if any
	if len(schemaInfo.Indexes) > 0 {
		fmt.Printf("\nIndexes (%d):\n", len(schemaInfo.Indexes))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  Name\tTable\tColumns\tType\tUnique\n")
		fmt.Fprintf(w, "  ----\t-----\t-------\t----\t------\n")

		for _, index := range schemaInfo.Indexes {
			unique := "NO"
			if index.Unique {
				unique = "YES"
			}

			columns := ""
			if len(index.Columns) > 0 {
				columns = fmt.Sprintf("[%s]", fmt.Sprintf("%v", index.Columns))
			}

			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
				index.Name, index.Table, columns, index.Type, unique)
		}
		w.Flush()
	}

	// Show triggers if any
	if len(schemaInfo.Triggers) > 0 {
		fmt.Printf("\nTriggers (%d):\n", len(schemaInfo.Triggers))
		for _, trigger := range schemaInfo.Triggers {
			fmt.Printf("  ⚡ %s on %s (%s %s)\n", trigger.Name, trigger.Table, trigger.Timing, trigger.Event)
			if detailed && trigger.Definition != "" {
				fmt.Printf("     Definition: %s\n", trigger.Definition)
			}
		}
	}

	return nil
}