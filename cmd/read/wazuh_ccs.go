// cmd/read/wazuh_ccs.go
package read

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// ReadWazuhCCSCmd reads Wazuh MSSP platform status and information
var ReadWazuhCCSCmd = &cobra.Command{
	Use:   "wazuh-ccs",
	Short: "Read Wazuh MSSP platform status and information",
	Long: `Read various information about the Wazuh MSSP platform:

- Platform status (--status)
- Customer details (--customer)
- Deployment health (--health)
- Resource usage (--resources)
- Event statistics (--events)`,
	RunE: eos_cli.Wrap(runReadWazuhCCS),
}

func init() {
	// NOTE: ReadWazuhCCSCmd is NO LONGER registered at top level
	// It is now accessed via: eos read wazuh --ccs
	// Top-level registration removed as part of command refactoring

	// Flags are still defined here for when called via wazuh.go router
	// Status flags
	ReadWazuhCCSCmd.Flags().Bool("status", false, "Show platform status")
	ReadWazuhCCSCmd.Flags().String("customer-id", "", "Customer ID for detailed status")

	// Customer information flags
	ReadWazuhCCSCmd.Flags().Bool("customer", false, "Show customer details")
	ReadWazuhCCSCmd.Flags().Bool("show-credentials", false, "Include credentials in output")

	// Health check flags
	ReadWazuhCCSCmd.Flags().Bool("health", false, "Show platform health")
	ReadWazuhCCSCmd.Flags().Bool("detailed", false, "Show detailed health information")

	// Resource usage flags
	ReadWazuhCCSCmd.Flags().Bool("resources", false, "Show resource usage")
	ReadWazuhCCSCmd.Flags().Bool("by-customer", false, "Group resources by customer")

	// Event statistics flags
	ReadWazuhCCSCmd.Flags().Bool("events", false, "Show event statistics")
	ReadWazuhCCSCmd.Flags().String("time-range", "1h", "Time range for statistics (1h/24h/7d)")

	// Output format
	ReadWazuhCCSCmd.Flags().String("output", "table", "Output format (table/json/yaml)")
}

func runReadWazuhCCS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Determine what to read
	showStatus, _ := cmd.Flags().GetBool("status")
	showCustomer, _ := cmd.Flags().GetBool("customer")
	showHealth, _ := cmd.Flags().GetBool("health")
	showResources, _ := cmd.Flags().GetBool("resources")
	showEvents, _ := cmd.Flags().GetBool("events")

	// Default to status if nothing specified
	if !showStatus && !showCustomer && !showHealth && !showResources && !showEvents {
		showStatus = true
	}

	outputFormat, _ := cmd.Flags().GetString("output")
	format := platform.OutputFormat(outputFormat)

	// Route to appropriate handler
	switch {
	case showStatus:
		customerID, _ := cmd.Flags().GetString("customer-id")
		if customerID != "" {
			status, err := platform.GetCustomerStatus(rc, customerID)
			if err != nil {
				return err
			}
			return platform.OutputCustomerStatus(logger, status, format)
		}
		status, err := platform.GetPlatformStatus(rc)
		if err != nil {
			return err
		}
		return platform.OutputPlatformStatus(logger, status, format)

	case showCustomer:
		customerID, _ := cmd.Flags().GetString("customer-id")
		showCreds, _ := cmd.Flags().GetBool("show-credentials")
		details, err := platform.GetCustomerDetails(rc, customerID, showCreds)
		if err != nil {
			return err
		}
		return platform.OutputCustomerDetails(logger, details, format)

	case showHealth:
		detailed, _ := cmd.Flags().GetBool("detailed")
		health, err := platform.GetPlatformHealth(rc, detailed)
		if err != nil {
			return err
		}
		return platform.OutputPlatformHealth(logger, health, format)

	case showResources:
		byCustomer, _ := cmd.Flags().GetBool("by-customer")
		if byCustomer {
			resources, err := platform.GetResourcesByCustomer(rc)
			if err != nil {
				return err
			}
			return platform.OutputCustomerResources(logger, resources, format)
		}
		resources, err := platform.GetResourceUsage(rc, byCustomer)
		if err != nil {
			return err
		}
		return platform.OutputPlatformResources(logger, resources, format)

	case showEvents:
		timeRange, _ := cmd.Flags().GetString("time-range")
		stats, err := platform.GetEventStatistics(rc, timeRange)
		if err != nil {
			return err
		}
		return platform.OutputEventStatistics(logger, stats, format)

	default:
		return cmd.Help()
	}
}
