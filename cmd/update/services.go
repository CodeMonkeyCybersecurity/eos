package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/output"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system/system_services"
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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		showAll, _ := cmd.Flags().GetBool("all")

		config := &system_services.ServiceConfig{
			ShowAll: showAll,
		}

		// Get flag values
		pattern, _ := cmd.Flags().GetString("pattern")
		stateFilter, _ := cmd.Flags().GetStringSlice("state")
		enabledStr, _ := cmd.Flags().GetString("enabled")
		runningStr, _ := cmd.Flags().GetString("running")

		// Parse enabled/running flags
		var enabled, running *bool
		if enabledStr != "" {
			switch enabledStr {
			case "true":
				val := true
				enabled = &val
			case "false":
				val := false
				enabled = &val
			default:
				return fmt.Errorf("invalid value for --enabled: %s (use true or false)", enabledStr)
			}
		}

		if runningStr != "" {
			switch runningStr {
			case "true":
				val := true
				running = &val
			case "false":
				val := false
				running = &val
			default:
				return fmt.Errorf("invalid value for --running: %s (use true or false)", runningStr)
			}
		}

		// Build filter options
		filter := &system_services.ServiceFilterOptions{
			Pattern: pattern,
			Enabled: enabled,
			Running: running,
		}

		// Parse state filter
		if len(stateFilter) > 0 {
			var states []system_services.ServiceState
			for _, s := range stateFilter {
				states = append(states, system_services.ServiceState(s))
			}
			filter.State = states
		}

		logger.Info("Listing services",
			zap.Bool("show_all", showAll),
			zap.String("pattern", pattern))

		// Use simplified function instead of manager pattern
		result, err := system_services.ListServices(rc, config, filter)
		if err != nil {
			return err
		}

		return output.ServiceListToStdout(result, outputJSON)
	}),
}

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
		enable, _ := cmd.Flags().GetBool("enable")

		serviceName := args[0]

		config := &system_services.ServiceConfig{
			DryRun: dryRun,
			Sudo:   sudo,
		}

		logger.Info("Starting service",
			zap.String("service", serviceName),
			zap.Bool("enable", enable),
			zap.Bool("dry_run", dryRun))

		// Use simplified function instead of manager pattern
		result, err := system_services.StartService(rc, config, serviceName, enable)
		if err != nil {
			return err
		}

		return output.ServiceOperationToStdout(result, outputJSON)
	}),
}

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
		disable, _ := cmd.Flags().GetBool("disable")

		serviceName := args[0]

		config := &system_services.ServiceConfig{
			DryRun: dryRun,
			Sudo:   sudo,
		}

		logger.Info("Stopping service",
			zap.String("service", serviceName),
			zap.Bool("disable", disable),
			zap.Bool("dry_run", dryRun))

		// Use simplified function instead of manager pattern
		result, err := system_services.StopService(rc, config, serviceName, disable)
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

		logger.Info("Restarting service",
			zap.String("service", serviceName),
			zap.Bool("dry_run", dryRun))

		// Use simplified function instead of manager pattern
		result, err := system_services.RestartService(rc, config, serviceName)
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

		logger.Info("Getting service status", zap.String("service", serviceName))

		// Use simplified function instead of manager pattern
		result, err := system_services.GetServiceStatus(rc, serviceName)
		if err != nil {
			return err
		}

		return output.ServiceStatusToStdout(result, outputJSON)
	}),
}

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

		// Get flag values
		follow, _ := cmd.Flags().GetBool("follow")
		lines, _ := cmd.Flags().GetInt("lines")
		since, _ := cmd.Flags().GetString("since")
		until, _ := cmd.Flags().GetString("until")
		priority, _ := cmd.Flags().GetString("priority")
		grep, _ := cmd.Flags().GetString("grep")
		reverse, _ := cmd.Flags().GetBool("reverse")
		noHostname, _ := cmd.Flags().GetBool("no-hostname")

		options := &system_services.LogsOptions{
			Follow:     follow,
			Lines:      lines,
			Since:      since,
			Until:      until,
			Priority:   priority,
			Unit:       serviceName,
			Grep:       grep,
			Reverse:    reverse,
			NoHostname: noHostname,
		}

		logger.Info("Viewing service logs",
			zap.String("service", serviceName),
			zap.Bool("follow", follow))

		// Use simplified function instead of manager pattern
		return system_services.ViewLogs(rc, serviceName, options)
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
	servicesCmd.PersistentFlags().Bool("json", false, "Output results in JSON format")
	servicesCmd.PersistentFlags().Bool("dry-run", false, "Show what would be done without making changes")
	servicesCmd.PersistentFlags().Bool("all", false, "Show all services including inactive")
	servicesCmd.PersistentFlags().Bool("sudo", true, "Use sudo for service operations")

	// Add flags for services list command
	servicesListCmd.Flags().StringSlice("state", nil, "Filter by service state (active,inactive,failed,etc)")
	servicesListCmd.Flags().String("pattern", "", "Filter services by name pattern (regex)")
	servicesListCmd.Flags().String("enabled", "", "Filter by enabled status (true/false)")
	servicesListCmd.Flags().String("running", "", "Filter by running status (true/false)")

	// Add flags for services start command
	servicesStartCmd.Flags().Bool("enable", false, "Also enable the service at boot")

	// Add flags for services stop command
	servicesStopCmd.Flags().Bool("disable", false, "Also disable the service at boot")

	// Add flags for services logs command
	servicesLogsCmd.Flags().BoolP("follow", "f", false, "Follow logs in real-time")
	servicesLogsCmd.Flags().IntP("lines", "n", 50, "Number of lines to show")
	servicesLogsCmd.Flags().String("since", "", "Show logs since this time (e.g., '1 hour ago')")
	servicesLogsCmd.Flags().String("until", "", "Show logs until this time")
	servicesLogsCmd.Flags().StringP("priority", "p", "", "Filter by priority (emerg, alert, crit, err, warning, notice, info, debug)")
	servicesLogsCmd.Flags().String("grep", "", "Filter logs by pattern")
	servicesLogsCmd.Flags().BoolP("reverse", "r", false, "Show newest entries first")
	servicesLogsCmd.Flags().Bool("no-hostname", false, "Don't show hostname field")
}
