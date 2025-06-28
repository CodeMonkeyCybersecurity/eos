/* cmd/delphi/dashboard/dashboard.go */

package dashboard

import (
	"database/sql"
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/dashboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	
	_ "github.com/lib/pq" // PostgreSQL driver
)

// NewDashboardCmd creates the main dashboard command
func NewDashboardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard [module]",
		Short: "Launch the interactive Delphi pipeline dashboard",
		Long: `Launch the interactive Delphi pipeline dashboard for comprehensive monitoring and management.

The dashboard provides multiple specialized modules accessible via function keys:

F1: Pipeline Monitor - Real-time pipeline flow and health monitoring
F2: Services Management - Interactive service control and monitoring  
F3: Parser Performance - Parser metrics and circuit breaker status
F4: Alert Analysis - Alert processing analysis and failure investigation
F5: Performance Metrics - System performance and resource monitoring
F6: Executive Overview - High-level KPIs and operational summary

Available modules:
- pipeline: Pipeline flow monitoring and bottleneck detection
- services: Interactive service management and control
- parsers: Parser performance and circuit breaker monitoring
- alerts: Alert analysis and failure investigation
- performance: System performance metrics
- overview: Executive dashboard with KPIs

Examples:
  eos delphi dashboard                    # Launch with overview (default)
  eos delphi dashboard services          # Launch directly to services module
  eos delphi dashboard pipeline          # Launch directly to pipeline module

Navigation:
- F1-F6: Switch between modules
- Tab/Shift+Tab: Navigate within modules
- ?: Context-sensitive help
- q: Quit dashboard
- Ctrl+R: Refresh all data`,
		ValidArgs: []string{"pipeline", "services", "parsers", "alerts", "performance", "overview"},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Starting Delphi dashboard")

			// Determine which module to start with
			startModule := dashboard.ModuleOverview // Default to overview
			if len(args) > 0 {
				switch args[0] {
				case "pipeline":
					startModule = dashboard.ModulePipeline
				case "services":
					startModule = dashboard.ModuleServices
				case "parsers":
					startModule = dashboard.ModuleParsers
				case "alerts":
					startModule = dashboard.ModuleAlerts
				case "performance":
					startModule = dashboard.ModulePerformance
				case "overview":
					startModule = dashboard.ModuleOverview
				default:
					return fmt.Errorf("unknown module: %s. Valid modules: pipeline, services, parsers, alerts, performance, overview", args[0])
				}
			}

			// Connect to database
			logger.Info("Connecting to Delphi database")
			db, err := connectToDatabase(rc)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %w", err)
			}
			defer func() {
				if closeErr := db.Close(); closeErr != nil {
					logger.Warn("Failed to close database connection", zap.Error(closeErr))
				}
			}()

			// Create dashboard hub
			logger.Info("Initializing dashboard hub",
				zap.String("start_module", startModule.String()))
			
			hub := dashboard.NewHub(rc, db)
			
			// Register available modules
			logger.Info("Registering dashboard modules")
			
			// Register services module
			servicesModule := dashboard.NewServicesModule(rc, db)
			hub.RegisterModule(servicesModule)
			
			// TODO: Register other modules as they are implemented
			// pipelineModule := dashboard.NewPipelineModule(rc, db)
			// hub.RegisterModule(pipelineModule)
			
			// parsersModule := dashboard.NewParsersModule(rc, db)
			// hub.RegisterModule(parsersModule)
			
			// alertsModule := dashboard.NewAlertsModule(rc, db)
			// hub.RegisterModule(alertsModule)
			
			// performanceModule := dashboard.NewPerformanceModule(rc, db)
			// hub.RegisterModule(performanceModule)
			
			// overviewModule := dashboard.NewOverviewModule(rc, db)
			// hub.RegisterModule(overviewModule)
			
			// Switch to requested starting module
			if startModule != dashboard.ModuleOverview {
				hub.SwitchToModule(startModule)
			}

			// Start the Bubble Tea program
			logger.Info("Launching dashboard interface")
			
			program := tea.NewProgram(
				hub, 
				tea.WithAltScreen(),
				tea.WithMouseCellMotion(),
			)

			// Run the program
			if _, err := program.Run(); err != nil {
				return fmt.Errorf("dashboard error: %w", err)
			}

			logger.Info("Dashboard session completed")
			return nil
		}),
	}

	return cmd
}

// connectToDatabase establishes a connection to the Delphi PostgreSQL database
func connectToDatabase(rc *eos_io.RuntimeContext) (*sql.DB, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// TODO: Get database connection string from configuration
	// For now, use environment variables or default values
	
	// This would typically come from:
	// - Environment variables (DELPHI_DB_*)
	// - Configuration files
	// - Vault secrets
	// - Command line flags
	
	connStr := "postgres://delphi:delphi@localhost/delphi?sslmode=disable"
	
	logger.Info("Connecting to PostgreSQL database",
		zap.String("connection", "localhost/delphi"))
	
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	
	// Test the connection
	if err := db.Ping(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			logger.Warn("Failed to close database after ping failure", zap.Error(closeErr))
		}
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	
	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	
	logger.Info("Database connection established successfully")
	return db, nil
}