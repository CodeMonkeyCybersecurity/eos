package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/output"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system_services"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// servicesCmd manages systemd services
var servicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Manage systemd services",
	Long: `Manage systemd services with comprehensive operations including start, stop, restart, 
enable, disable, and log viewing.

This command provides a unified interface for systemd service management with support for:
- Listing services with filtering options
- Starting and stopping services
- Enabling and disabling services at boot
- Viewing service logs with various options
- Dry-run mode for safe operations

Examples:
  eos manage services list                    # List active services
  eos manage services list --all              # List all services
  eos manage services start nginx             # Start nginx service
  eos manage services stop nginx --disable    # Stop and disable nginx
  eos manage services logs nginx --follow     # Follow nginx logs
  eos manage services status nginx            # Get detailed service status`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for services", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// Flag variables for services list command
var (
	servicesListState      []string
	servicesListPattern    string
	servicesListEnabled    *bool
	servicesListRunning    *bool
	servicesListEnabledStr string
	servicesListRunningStr string
)

// servicesListCmd lists systemd services
var servicesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List systemd services",
	Long: `List systemd services with optional filtering.

Available filters:
- State: active, inactive, failed, activating, deactivating
- Pattern: Regular expression to match service names
- Enabled: Filter by whether services are enabled at boot
- Running: Filter by whether services are currently running

Examples:
  eos manage services list                           # List active services
  eos manage services list --all                     # List all services
  eos manage services list --state active,failed     # List active and failed services
  eos manage services list --pattern "nginx.*"       # List services matching pattern
  eos manage services list --enabled=true            # List enabled services
  eos manage services list --running=false           # List stopped services`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if servicesListEnabledStr != "" {
			if servicesListEnabledStr == "true" {
				val := true
				servicesListEnabled = &val
			} else if servicesListEnabledStr == "false" {
				val := false
				servicesListEnabled = &val
			} else {
				return fmt.Errorf("invalid value for --enabled: %s (use true or false)", servicesListEnabledStr)
			}
		}

		if servicesListRunningStr != "" {
			if servicesListRunningStr == "true" {
				val := true
				servicesListRunning = &val
			} else if servicesListRunningStr == "false" {
				val := false
				servicesListRunning = &val
			} else {
				return fmt.Errorf("invalid value for --running: %s (use true or false)", servicesListRunningStr)
			}
		}

		return nil
	},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		showAll, _ := cmd.Flags().GetBool("all")

		config := &system_services.ServiceConfig{
			ShowAll: showAll,
		}

		manager := system_services.NewServiceManager(config)

		// Build filter options
		filter := &system_services.ServiceFilterOptions{
			Pattern: servicesListPattern,
			Enabled: servicesListEnabled,
			Running: servicesListRunning,
		}

		// Parse state filter
		if len(servicesListState) > 0 {
			var states []system_services.ServiceState
			for _, s := range servicesListState {
				states = append(states, system_services.ServiceState(s))
			}
			filter.State = states
		}

		logger.Info("Listing services",
			zap.Bool("show_all", showAll),
			zap.String("pattern", servicesListPattern))

		result, err := manager.ListServices(rc, filter)
		if err != nil {
			return err
		}

		return output.ServiceListToStdout(result, outputJSON)
	}),
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// Flag variables for services start command
var servicesStartEnable bool

// servicesStartCmd starts a systemd service
var servicesStartCmd = &cobra.Command{
	Use:   "start <service>",
	Short: "Start a systemd service",
	Long: `Start a systemd service and optionally enable it at boot.

This command starts the specified service immediately. If the --enable flag
is provided, the service will also be enabled to start automatically at boot.

Examples:
  eos manage services start nginx           # Start nginx service
  eos manage services start nginx --enable # Start and enable nginx service
  eos manage services start nginx --dry-run # Preview what would happen`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		sudo, _ := cmd.Flags().GetBool("sudo")

		serviceName := args[0]

		config := &system_services.ServiceConfig{
			DryRun: dryRun,
			Sudo:   sudo,
		}

		manager := system_services.NewServiceManager(config)

		logger.Info("Starting service",
			zap.String("service", serviceName),
			zap.Bool("enable", servicesStartEnable),
			zap.Bool("dry_run", dryRun))

		result, err := manager.StartService(rc, serviceName, servicesStartEnable)
		if err != nil {
			return err
		}

		return output.ServiceOperationToStdout(result, outputJSON)
	}),
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// Flag variables for services stop command
var servicesStopDisable bool

// servicesStopCmd stops a systemd service
var servicesStopCmd = &cobra.Command{
	Use:   "stop <service>",
	Short: "Stop a systemd service",
	Long: `Stop a systemd service and optionally disable it at boot.

This command stops the specified service immediately. If the --disable flag
is provided, the service will also be disabled from starting automatically at boot.

Examples:
  eos manage services stop nginx            # Stop nginx service
  eos manage services stop nginx --disable # Stop and disable nginx service
  eos manage services stop nginx --dry-run # Preview what would happen`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		sudo, _ := cmd.Flags().GetBool("sudo")

		serviceName := args[0]

		config := &system_services.ServiceConfig{
			DryRun: dryRun,
			Sudo:   sudo,
		}

		manager := system_services.NewServiceManager(config)

		logger.Info("Stopping service",
			zap.String("service", serviceName),
			zap.Bool("disable", servicesStopDisable),
			zap.Bool("dry_run", dryRun))

		result, err := manager.StopService(rc, serviceName, servicesStopDisable)
		if err != nil {
			return err
		}

		return output.ServiceOperationToStdout(result, outputJSON)
	}),
}

// servicesRestartCmd restarts a systemd service
var servicesRestartCmd = &cobra.Command{
	Use:   "restart <service>",
	Short: "Restart a systemd service",
	Long: `Restart a systemd service.

This command stops and then starts the specified service. This is useful for
applying configuration changes or recovering from service issues.

Examples:
  eos manage services restart nginx         # Restart nginx service
  eos manage services restart nginx --dry-run # Preview what would happen`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		sudo, _ := cmd.Flags().GetBool("sudo")

		serviceName := args[0]

		config := &system_services.ServiceConfig{
			DryRun: dryRun,
			Sudo:   sudo,
		}

		manager := system_services.NewServiceManager(config)

		logger.Info("Restarting service",
			zap.String("service", serviceName),
			zap.Bool("dry_run", dryRun))

		result, err := manager.RestartService(rc, serviceName)
		if err != nil {
			return err
		}

		return output.ServiceOperationToStdout(result, outputJSON)
	}),
}

// servicesStatusCmd gets detailed status for a systemd service
var servicesStatusCmd = &cobra.Command{
	Use:   "status <service>",
	Short: "Get detailed status for a systemd service",
	Long: `Get detailed status information for a systemd service.

This command provides comprehensive information about a service including:
- Current state (active, inactive, failed, etc.)
- Whether the service is enabled at boot
- Load state and unit file information
- Service description

Examples:
  eos manage services status nginx          # Get nginx service status
  eos manage services status nginx --json  # Get status in JSON format`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		serviceName := args[0]

		manager := system_services.NewServiceManager(nil)

		logger.Info("Getting service status", zap.String("service", serviceName))

		result, err := manager.GetServiceStatus(rc, serviceName)
		if err != nil {
			return err
		}

		return output.ServiceStatusToStdout(result, outputJSON)
	}),
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// Flag variables for services logs command
var (
	servicesLogsFollow     bool
	servicesLogsLines      int
	servicesLogsSince      string
	servicesLogsUntil      string
	servicesLogsPriority   string
	servicesLogsGrep       string
	servicesLogsReverse    bool
	servicesLogsNoHostname bool
)

// servicesLogsCmd views logs for a systemd service
var servicesLogsCmd = &cobra.Command{
	Use:   "logs <service>",
	Short: "View logs for a systemd service",
	Long: `View logs for a systemd service using journalctl.

This command provides flexible log viewing with options for:
- Following logs in real-time
- Limiting number of lines
- Filtering by time range
- Filtering by priority level
- Grep pattern matching
- Reverse chronological order

Examples:
  eos manage services logs nginx             # Show recent logs
  eos manage services logs nginx --follow    # Follow logs in real-time
  eos manage services logs nginx --lines 100 # Show last 100 lines
  eos manage services logs nginx --since "1 hour ago"
  eos manage services logs nginx --grep "error"
  eos manage services logs nginx --priority err`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		serviceName := args[0]

		options := &system_services.LogsOptions{
			Follow:     servicesLogsFollow,
			Lines:      servicesLogsLines,
			Since:      servicesLogsSince,
			Until:      servicesLogsUntil,
			Priority:   servicesLogsPriority,
			Unit:       serviceName,
			Grep:       servicesLogsGrep,
			Reverse:    servicesLogsReverse,
			NoHostname: servicesLogsNoHostname,
		}

		manager := system_services.NewServiceManager(nil)

		logger.Info("Viewing service logs",
			zap.String("service", serviceName),
			zap.Bool("follow", servicesLogsFollow))

		return manager.ViewLogs(rc, serviceName, options)
	}),
}

// All output formatting functions have been moved to pkg/output/services.go

// init registers services commands and their flags
func init() {
	// Register services command with update command
	UpdateCmd.AddCommand(servicesCmd)
	
	// Add subcommands to services command
	servicesCmd.AddCommand(servicesListCmd)
	servicesCmd.AddCommand(servicesStartCmd)
	servicesCmd.AddCommand(servicesStopCmd)
	servicesCmd.AddCommand(servicesRestartCmd)
	servicesCmd.AddCommand(servicesStatusCmd)
	servicesCmd.AddCommand(servicesLogsCmd)

	// Add persistent flags for services command
	servicesCmd.PersistentFlags().BoolVar(&servicesOutputJSON, "json", false, "Output results in JSON format")
	servicesCmd.PersistentFlags().BoolVar(&servicesDryRun, "dry-run", false, "Show what would be done without making changes")
	servicesCmd.PersistentFlags().BoolVar(&servicesShowAll, "all", false, "Show all services including inactive")
	servicesCmd.PersistentFlags().BoolVar(&servicesSudo, "sudo", true, "Use sudo for service operations")

	// Add flags for services list command
	servicesListCmd.Flags().StringSliceVar(&servicesListState, "state", nil, "Filter by service state (active,inactive,failed,etc)")
	servicesListCmd.Flags().StringVar(&servicesListPattern, "pattern", "", "Filter services by name pattern (regex)")
	servicesListCmd.Flags().StringVar(&servicesListEnabledStr, "enabled", "", "Filter by enabled status (true/false)")
	servicesListCmd.Flags().StringVar(&servicesListRunningStr, "running", "", "Filter by running status (true/false)")

	// Add flags for services start command
	servicesStartCmd.Flags().BoolVar(&servicesStartEnable, "enable", false, "Also enable the service at boot")

	// Add flags for services stop command
	servicesStopCmd.Flags().BoolVar(&servicesStopDisable, "disable", false, "Also disable the service at boot")

	// Add flags for services logs command
	servicesLogsCmd.Flags().BoolVarP(&servicesLogsFollow, "follow", "f", false, "Follow logs in real-time")
	servicesLogsCmd.Flags().IntVarP(&servicesLogsLines, "lines", "n", 50, "Number of lines to show")
	servicesLogsCmd.Flags().StringVar(&servicesLogsSince, "since", "", "Show logs since this time (e.g., '1 hour ago')")
	servicesLogsCmd.Flags().StringVar(&servicesLogsUntil, "until", "", "Show logs until this time")
	servicesLogsCmd.Flags().StringVarP(&servicesLogsPriority, "priority", "p", "", "Filter by priority (emerg, alert, crit, err, warning, notice, info, debug)")
	servicesLogsCmd.Flags().StringVar(&servicesLogsGrep, "grep", "", "Filter logs by pattern")
	servicesLogsCmd.Flags().BoolVarP(&servicesLogsReverse, "reverse", "r", false, "Show newest entries first")
	servicesLogsCmd.Flags().BoolVar(&servicesLogsNoHostname, "no-hostname", false, "Don't show hostname field")
}
