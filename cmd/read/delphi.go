/* cmd/delphi/inspect/inspect.go */

package read

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	tea "github.com/charmbracelet/bubbletea"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	showSecrets bool
)

var readDelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Read Delphi (Wazuh) data",
	Long: `The 'read' command provides diagnostic and introspection tools for your Delphi (Wazuh) instance.

Use this command to view configuration details, authentication info, 
user permissions, versioning data, keepalive status, and other useful insights.

Subcommands are required to specify which type of information to read.`,
	Aliases: []string{"inspect", "get"}, // Keep aliases 'inspect' and 'get' if desired
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If this command is meant to be a parent (requiring subcommands like 'eos delphi inspect alerts'),
		// then its RunE should indicate missing subcommand and display its own help.
		otelzap.Ctx(rc.Ctx).Info("'eos delphi read' was called without a subcommand")

		fmt.Println(" Missing subcommand for 'eos delphi read'.")                                // More specific message
		fmt.Println("  Run `eos delphi read --help` to see available options for reading data.") // More specific advice
		_ = cmd.Help()                                                                           // Print built-in help for 'read' command
		return nil
	}),
}

// inspectCmd provides inspection tools for Delphi components
var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect Delphi components and pipeline functionality",
	Long: `Interactive inspection tools for Delphi monitoring system.
		
Available commands:
  pipeline-functionality - Interactive dashboard for pipeline monitoring
  verify-pipeline-schema  - Verify database schema matches schema.sql`,
	Aliases: []string{"get", "read"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

// pipelineFunctionalityCmd launches the interactive pipeline dashboard
var pipelineFunctionalityCmd = &cobra.Command{
	Use:   "pipeline-functionality",
	Short: "Interactive dashboard for Delphi pipeline monitoring",
	Long: `Launch an interactive terminal dashboard to monitor the Delphi pipeline.

The dashboard provides real-time views of:
- Pipeline health across all stages (new → enriched → analyzed → structured → formatted → sent)
- Bottleneck detection and performance metrics
- Parser performance statistics
- Recent failures with diagnostic information
- Daily operations summary

Navigation:
- Use ← → (or h/l) to switch between views
- Use ↑ ↓ (or k/j) to navigate within tables
- Press 'r' to refresh data
- Press '?' for help
- Press 'q' to quit

The dashboard connects to your PostgreSQL database and uses the pipeline monitoring views
defined in schema.sql to provide comprehensive visibility into your alert processing pipeline.`,
	Example: `  # Launch the interactive pipeline dashboard
  eos delphi inspect pipeline-functionality
  
  # This will connect to your Delphi database and display:
  # - Real-time pipeline flow visualization
  # - Performance bottleneck analysis
  # - Error rate monitoring
  # - Historical trend analysis`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting Delphi pipeline functionality dashboard")

		// Get database connection from Delphi configuration
		db, err := connectToDelphiDatabase(rc)
		if err != nil {
			logger.Error(" Failed to connect to Delphi database",
				zap.Error(err),
				zap.String("troubleshooting", "Ensure PostgreSQL is running and Delphi configuration is correct"))
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				logger.Warn(" Failed to close database connection", zap.Error(closeErr))
			}
		}()

		logger.Info(" Database connection established")

		// Verify database schema
		if err := verifyDatabaseSchema(rc, db); err != nil {
			logger.Warn(" Database schema verification failed",
				zap.Error(err),
				zap.String("note", "Some dashboard features may not work correctly"))
		}

		// Initialize and run the Bubble Tea dashboard
		logger.Info("🎛️ Launching interactive dashboard",
			zap.String("controls", "Use ←/→ to navigate, 'r' to refresh, 'q' to quit"))

		dashboardModel := delphi.InitializeDashboard(db, rc)

		// Create a Bubble Tea program
		program := tea.NewProgram(
			dashboardModel,
			tea.WithAltScreen(),
			tea.WithMouseCellMotion(),
		)

		// Run the program
		if _, err := program.Run(); err != nil {
			logger.Error(" Dashboard terminated with error",
				zap.Error(err))
			return fmt.Errorf("dashboard error: %w", err)
		}

		logger.Info(" Dashboard session completed")
		return nil
	}),
}

// verifyPipelineSchemaCmd verifies database schema
var verifyPipelineSchemaCmd = &cobra.Command{
	Use:   "verify-pipeline-schema",
	Short: "Verify database schema matches schema.sql requirements",
	Long: `Comprehensive verification of the Delphi database schema.

This command systematically checks your PostgreSQL database to ensure it matches
the expected schema.sql structure required for proper pipeline operation.

The verification includes:
- ENUM types (alert_state, parser_type)
- Core tables (agents, alerts, parser_metrics) with column validation
- Performance indexes for optimal query speed
- Monitoring views (pipeline_health, parser_performance, etc.)
- Pipeline functions (archive_old_alerts, get_pipeline_stats, etc.)
- State change triggers for real-time notifications

For each component, the tool reports:
✓ EXISTS       - Component is properly configured
⚠ EXISTS BUT BROKEN - Component exists but may need recreation
✗ MISSING      - Component needs to be created
✗ CANNOT VERIFY - Prerequisites are missing

Example Output:
  ENUM Types:
    ✓ EXISTS        alert_state (6 values: new, enriched, analyzed, structured, formatted, sent)
    ✓ EXISTS        parser_type (11 values: ossec, windows_eventchannel, syslog, ...)
  
  Tables:
    ✓ EXISTS        agents (6 columns)
    ✓ EXISTS        alerts (20 columns)
    ✓ EXISTS        parser_metrics (4 columns)
  
  Indexes:
    ✓ EXISTS        idx_alerts_timestamp
    ✗ MISSING       idx_alerts_state_timestamp
  
  Views:
    ✓ EXISTS        pipeline_health
    ⚠ EXISTS BUT BROKEN   parser_performance (missing column: avg_parse_time)
  
  Functions:
    ✓ EXISTS        archive_old_alerts()
    ✗ MISSING       get_pipeline_stats()
  
  Triggers:
    ✓ EXISTS        notify_alert_state_change

Use this tool after database migrations or when troubleshooting pipeline issues
to ensure your database schema is properly configured.`,
	Example: `  # Verify the Delphi database schema
  eos delphi inspect verify-pipeline-schema
  
  # The command will connect to your database and verify:
  # - All required database objects exist
  # - Table structures match expectations
  # - Performance optimizations are in place
  # - Monitoring infrastructure is configured`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Verifying Delphi pipeline database schema")

		// Connect to database
		db, err := connectToDelphiDatabase(rc)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer db.Close()

		// Create schema verifier
		verifier := delphi.NewSchemaVerifier(db)

		// Run verification
		result, err := verifier.VerifyCompleteSchema(rc)
		if err != nil {
			return fmt.Errorf("schema verification failed: %w", err)
		}

		// Display results
		fmt.Printf("\n=== Delphi Pipeline Schema Verification ===\n")
		fmt.Printf("Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
		fmt.Printf("Overall Status: %s\n", result.OverallStatus)
		fmt.Printf("Missing Objects: %d\n\n", result.MissingCount)

		// Display detailed results for each object type
		displaySchemaObjects("Enum Types", result.EnumTypes)
		displaySchemaObjects("Tables", result.Tables)
		displaySchemaObjects("Indexes", result.Indexes)
		displaySchemaObjects("Views", result.Views)
		displaySchemaObjects("Functions", result.Functions)
		displaySchemaObjects("Triggers", result.Triggers)

		if result.MissingCount > 0 {
			fmt.Printf("\n⚠️  Schema verification found %d missing objects.\n", result.MissingCount)
			fmt.Println("Run 'eos create delphi deploy' to deploy the complete schema.")
		} else {
			fmt.Println("\n All schema objects are present and verified.")
		}

		return nil
	}),
}

func init() {
	// Add subcommands to the delphi read command
	readDelphiCmd.AddCommand(delphiAgentsCmd)
	readDelphiCmd.AddCommand(delphiDashboardCmd)
	readDelphiCmd.AddCommand(ReadKeepAliveCmd)

	// Add the inspect command with its subcommands
	inspectCmd.AddCommand(pipelineFunctionalityCmd)
	inspectCmd.AddCommand(verifyPipelineSchemaCmd)
	readDelphiCmd.AddCommand(inspectCmd)

	// Add any flags specific to 'read' itself, if it were a terminal command or had persistent flags.
	// ReadCmd.Flags().BoolVarP(&showSecrets, "show-secrets", "s", false, "Show sensitive secret values (use with caution)")
}

// displaySchemaObjects displays verification results for a specific object type
// TODO: Move to pkg/delphi/display or pkg/delphi/output
func displaySchemaObjects(objectType string, objects []delphi.SchemaObject) {
	if len(objects) == 0 {
		return
	}

	fmt.Printf("\n%s:\n", objectType)
	for _, obj := range objects {
		statusSymbol := "✓"
		if obj.Status != "OK" {
			statusSymbol = "✗"
		}

		fmt.Printf("  %s %s", statusSymbol, obj.Name)
		if obj.Details != "" {
			fmt.Printf(" - %s", obj.Details)
		}
		if obj.ActionNeeded != "" {
			fmt.Printf("\n    Action: %s", obj.ActionNeeded)
		}
		fmt.Println()
	}
}

// connectToDelphiDatabase establishes a connection to the Delphi PostgreSQL database
// TODO: Move to pkg/delphi/database or pkg/database_management
func connectToDelphiDatabase(rc *eos_io.RuntimeContext) (*sql.DB, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Build database connection string
	// Default to standard PostgreSQL settings, but allow override from environment
	dbHost := "localhost"
	dbPort := "5432"
	dbName := "delphi"
	dbUser := "delphi"
	dbPassword := "delphi"

	// Use environment variables if available
	if envHost := os.Getenv("DELPHI_DB_HOST"); envHost != "" {
		dbHost = envHost
	}
	if envPort := os.Getenv("DELPHI_DB_PORT"); envPort != "" {
		dbPort = envPort
	}
	if envName := os.Getenv("DELPHI_DB_NAME"); envName != "" {
		dbName = envName
	}
	if envUser := os.Getenv("DELPHI_DB_USER"); envUser != "" {
		dbUser = envUser
	}
	if envPassword := os.Getenv("DELPHI_DB_PASSWORD"); envPassword != "" {
		dbPassword = envPassword
	}

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=prefer TimeZone=UTC",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	logger.Info("🔌 Connecting to Delphi database",
		zap.String("host", dbHost),
		zap.String("port", dbPort),
		zap.String("database", dbName),
		zap.String("user", dbUser))

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			logger.Warn(" Failed to close database connection after ping failure", zap.Error(closeErr))
		}
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	return db, nil
}

// verifyDatabaseSchema checks that required views and tables exist
// TODO: Move to pkg/delphi/database or pkg/delphi/schema
func verifyDatabaseSchema(rc *eos_io.RuntimeContext, db *sql.DB) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Verifying database schema")

	requiredViews := []string{
		"pipeline_health",
		"pipeline_bottlenecks",
		"parser_performance",
		"recent_failures",
	}

	requiredTables := []string{
		"alerts",
		"agents",
		"parser_metrics",
	}

	// Check views
	for _, view := range requiredViews {
		var exists bool
		query := `SELECT EXISTS (
			SELECT 1 FROM information_schema.views 
			WHERE table_schema = 'public' AND table_name = $1
		)`

		if err := db.QueryRow(query, view).Scan(&exists); err != nil {
			logger.Error(" Error checking view existence",
				zap.String("view", view),
				zap.Error(err))
			return fmt.Errorf("error checking view %s: %w", view, err)
		}

		if !exists {
			logger.Warn(" Required view missing",
				zap.String("view", view),
				zap.String("recommendation", "Run database migrations to create monitoring views"))
		} else {
			logger.Debug("✓ View exists", zap.String("view", view))
		}
	}

	// Check tables
	for _, table := range requiredTables {
		var exists bool
		query := `SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_schema = 'public' AND table_name = $1
		)`

		if err := db.QueryRow(query, table).Scan(&exists); err != nil {
			logger.Error(" Error checking table existence",
				zap.String("table", table),
				zap.Error(err))
			return fmt.Errorf("error checking table %s: %w", table, err)
		}

		if !exists {
			logger.Warn(" Required table missing",
				zap.String("table", table),
				zap.String("recommendation", "Run database migrations to create required tables"))
		} else {
			logger.Debug("✓ Table exists", zap.String("table", table))
		}
	}

	logger.Info(" Database schema verification completed")
	return nil
}
