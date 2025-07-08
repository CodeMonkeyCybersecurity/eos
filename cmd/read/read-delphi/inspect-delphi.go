/* cmd/delphi/inspect/inspect.go */

package inspect

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	tea "github.com/charmbracelet/bubbletea"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewInspectCmd creates the inspect command with subcommands
func NewInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
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

	// Add subcommands
	cmd.AddCommand(NewPipelineFunctionalityCmd())
	cmd.AddCommand(NewVerifyPipelineSchemaCmd())

	return cmd
}

// NewPipelineFunctionalityCmd creates the pipeline-functionality command
func NewPipelineFunctionalityCmd() *cobra.Command {
	cmd := &cobra.Command{
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
		RunE: eos_cli.Wrap(runPipelineFunctionalityDashboard),
	}

	return cmd
}

// runPipelineFunctionalityDashboard launches the interactive Bubble Tea dashboard
func runPipelineFunctionalityDashboard(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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
}

// connectToDelphiDatabase establishes a connection to the Delphi PostgreSQL database
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

// NewVerifyPipelineSchemaCmd creates the verify-pipeline-schema command
func NewVerifyPipelineSchemaCmd() *cobra.Command {
	cmd := &cobra.Command{
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

The tool provides specific SQL commands to fix any issues found.`,
		Example: `  # Verify the complete schema
  eos delphi inspect verify-pipeline-schema
  
  # Example output:
  #  Database fully matches schema.sql!
  # OR
  #  Database requires updates: 3 missing objects, 1 warnings
  #
  # The report will show exactly what needs to be fixed:
  # - Missing enum types with CREATE TYPE commands
  # - Missing tables with references to schema.sql
  # - Missing indexes affecting performance
  # - Broken views that need recreation`,
		RunE: eos_cli.Wrap(runVerifyPipelineSchema),
	}

	return cmd
}

// runVerifyPipelineSchema performs comprehensive schema verification
func runVerifyPipelineSchema(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting database schema verification")

	// Connect to database
	db, err := connectToDelphiDatabase(rc)
	if err != nil {
		logger.Error(" Failed to connect to Delphi database",
			zap.Error(err),
			zap.String("troubleshooting", "Ensure PostgreSQL is running and connection parameters are correct"))
		return fmt.Errorf("database connection failed: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			logger.Warn(" Failed to close database connection", zap.Error(closeErr))
		}
	}()

	logger.Info(" Database connection established")

	// Create schema verifier and run verification
	verifier := delphi.NewSchemaVerifier(db)
	result, err := verifier.VerifyCompleteSchema(rc)
	if err != nil {
		logger.Error(" Schema verification failed",
			zap.Error(err))
		return fmt.Errorf("verification failed: %w", err)
	}

	// Generate and display the report
	report := result.GenerateReport()

	// Log the summary
	logger.Info(" Schema verification completed",
		zap.String("overall_status", result.OverallStatus),
		zap.Int("missing_objects", result.MissingCount),
		zap.Time("verification_time", result.Timestamp))

	// Print the full report to stdout (this is what users will see)
	fmt.Print(report)

	// Return non-zero exit code if there are missing objects
	if result.MissingCount > 0 {
		logger.Warn(" Schema verification found issues - see report above")
		return fmt.Errorf("schema verification found %d missing objects", result.MissingCount)
	}

	logger.Info(" Schema verification passed - database is properly configured")
	return nil
}
