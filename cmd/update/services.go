package update

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system_services"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewServicesCmd creates the services command
func NewServicesCmd() *cobra.Command {
	var (
		outputJSON bool
		dryRun     bool
		showAll    bool
		sudo       bool
	)

	cmd := &cobra.Command{
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

	// Add subcommands
	cmd.AddCommand(NewServicesListCmd())
	cmd.AddCommand(NewServicesStartCmd())
	cmd.AddCommand(NewServicesStopCmd())
	cmd.AddCommand(NewServicesRestartCmd())
	cmd.AddCommand(NewServicesStatusCmd())
	cmd.AddCommand(NewServicesLogsCmd())

	// Add persistent flags
	cmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output results in JSON format")
	cmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.PersistentFlags().BoolVar(&showAll, "all", false, "Show all services including inactive")
	cmd.PersistentFlags().BoolVar(&sudo, "sudo", true, "Use sudo for service operations")

	return cmd
}

// NewServicesListCmd creates the list subcommand
func NewServicesListCmd() *cobra.Command {
	var (
		state   []string
		pattern string
		enabled *bool
		running *bool
	)

	cmd := &cobra.Command{
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

			manager := system_services.NewServiceManager(config)

			// Build filter options
			filter := &system_services.ServiceFilterOptions{
				Pattern: pattern,
				Enabled: enabled,
				Running: running,
			}

			// Parse state filter
			if len(state) > 0 {
				var states []system_services.ServiceState
				for _, s := range state {
					states = append(states, system_services.ServiceState(s))
				}
				filter.State = states
			}

			logger.Info("Listing services",
				zap.Bool("show_all", showAll),
				zap.String("pattern", pattern))

			result, err := manager.ListServices(rc, filter)
			if err != nil {
				return err
			}

			return outputServiceList(result, outputJSON)
		}),
	}

	cmd.Flags().StringSliceVar(&state, "state", nil, "Filter by service state (active,inactive,failed,etc)")
	cmd.Flags().StringVar(&pattern, "pattern", "", "Filter services by name pattern (regex)")

	// Use string flags for nullable booleans and parse them manually
	var enabledStr, runningStr string
	cmd.Flags().StringVar(&enabledStr, "enabled", "", "Filter by enabled status (true/false)")
	cmd.Flags().StringVar(&runningStr, "running", "", "Filter by running status (true/false)")

	// Parse nullable bool flags
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if enabledStr != "" {
			if enabledStr == "true" {
				val := true
				enabled = &val
			} else if enabledStr == "false" {
				val := false
				enabled = &val
			} else {
				return fmt.Errorf("invalid value for --enabled: %s (use true or false)", enabledStr)
			}
		}

		if runningStr != "" {
			if runningStr == "true" {
				val := true
				running = &val
			} else if runningStr == "false" {
				val := false
				running = &val
			} else {
				return fmt.Errorf("invalid value for --running: %s (use true or false)", runningStr)
			}
		}

		return nil
	}

	return cmd
}

// NewServicesStartCmd creates the start subcommand
func NewServicesStartCmd() *cobra.Command {
	var enable bool

	cmd := &cobra.Command{
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
				zap.Bool("enable", enable),
				zap.Bool("dry_run", dryRun))

			result, err := manager.StartService(rc, serviceName, enable)
			if err != nil {
				return err
			}

			return outputServiceOperation(result, outputJSON)
		}),
	}

	cmd.Flags().BoolVar(&enable, "enable", false, "Also enable the service at boot")

	return cmd
}

// NewServicesStopCmd creates the stop subcommand
func NewServicesStopCmd() *cobra.Command {
	var disable bool

	cmd := &cobra.Command{
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
				zap.Bool("disable", disable),
				zap.Bool("dry_run", dryRun))

			result, err := manager.StopService(rc, serviceName, disable)
			if err != nil {
				return err
			}

			return outputServiceOperation(result, outputJSON)
		}),
	}

	cmd.Flags().BoolVar(&disable, "disable", false, "Also disable the service at boot")

	return cmd
}

// NewServicesRestartCmd creates the restart subcommand
func NewServicesRestartCmd() *cobra.Command {
	cmd := &cobra.Command{
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

			return outputServiceOperation(result, outputJSON)
		}),
	}

	return cmd
}

// NewServicesStatusCmd creates the status subcommand
func NewServicesStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
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

			return outputServiceStatus(result, outputJSON)
		}),
	}

	return cmd
}

// NewServicesLogsCmd creates the logs subcommand
func NewServicesLogsCmd() *cobra.Command {
	var (
		follow     bool
		lines      int
		since      string
		until      string
		priority   string
		grep       string
		reverse    bool
		noHostname bool
	)

	cmd := &cobra.Command{
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

			manager := system_services.NewServiceManager(nil)

			logger.Info("Viewing service logs",
				zap.String("service", serviceName),
				zap.Bool("follow", follow))

			return manager.ViewLogs(rc, serviceName, options)
		}),
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow logs in real-time")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "Number of lines to show")
	cmd.Flags().StringVar(&since, "since", "", "Show logs since this time (e.g., '1 hour ago')")
	cmd.Flags().StringVar(&until, "until", "", "Show logs until this time")
	cmd.Flags().StringVarP(&priority, "priority", "p", "", "Filter by priority (emerg, alert, crit, err, warning, notice, info, debug)")
	cmd.Flags().StringVar(&grep, "grep", "", "Filter logs by pattern")
	cmd.Flags().BoolVarP(&reverse, "reverse", "r", false, "Show newest entries first")
	cmd.Flags().BoolVar(&noHostname, "no-hostname", false, "Don't show hostname field")

	return cmd
}

// Helper functions for output formatting

func outputServiceList(result *system_services.ServiceListResult, outputJSON bool) error {
	if outputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Text output
	fmt.Printf("Systemd Services (found %d):\n", result.Count)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("%-30s %-10s %-10s %-15s %s\n", "NAME", "LOAD", "ACTIVE", "SUB", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 80))

	for _, service := range result.Services {
		// Truncate description if too long
		desc := service.Description
		if len(desc) > 35 {
			desc = desc[:32] + "..."
		}

		fmt.Printf("%-30s %-10s %-10s %-15s %s\n",
			service.Name, service.LoadState, service.ActiveState,
			service.SubState, desc)
	}

	return nil
}

func outputServiceOperation(result *system_services.ServiceOperation, outputJSON bool) error {
	if outputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Text output
	fmt.Printf("Service Operation: %s\n", result.Operation)
	fmt.Printf("Service: %s\n", result.Service)
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("=", 50))

	if result.Success {
		fmt.Println("Operation completed successfully!")
	} else {
		fmt.Println("❌ Operation failed!")
	}

	fmt.Printf("\nMessage: %s\n", result.Message)

	if result.DryRun {
		fmt.Println("\n🔍 This was a dry run - no actual changes were made.")
	}

	return nil
}

func outputServiceStatus(result *system_services.ServiceInfo, outputJSON bool) error {
	if outputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Text output
	fmt.Printf("Service Status: %s\n", result.Name)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Description: %s\n", result.Description)
	fmt.Printf("Load State: %s\n", result.LoadState)
	fmt.Printf("Active State: %s\n", result.ActiveState)
	fmt.Printf("Sub State: %s\n", result.SubState)

	if result.Running {
		fmt.Println("Status: RUNNING")
	} else {
		fmt.Println("Status: ❌ NOT RUNNING")
	}

	if result.Enabled {
		fmt.Println("Boot Status: ENABLED")
	} else {
		fmt.Println("Boot Status: ❌ DISABLED")
	}

	if result.UnitFile != "" {
		fmt.Printf("Unit File: %s\n", result.UnitFile)
	}

	return nil
}
