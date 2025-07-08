/* cmd/delphi/dashboard/dashboard.go */

package dashboard

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/dashboard"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/database"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
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

			// Connect to database using Vault integration
			logger.Info("Connecting to Delphi database")
			db, err := database.Connect(rc)
			if err != nil {
				logger.Error("Database connection failed", zap.Error(err))
				logger.Info("Troubleshooting steps:",
					zap.String("step_1", "Check if database credentials are set: eos self secrets status"),
					zap.String("step_2", "Configure database credentials: eos self secrets set delphi-db"),
					zap.String("step_3", "Test Vault connectivity: eos self secrets test"),
					zap.String("step_4", "Verify database server is running and accessible"))
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