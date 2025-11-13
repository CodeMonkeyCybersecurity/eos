// cmd/list/wazuh_ccs.go
package list

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared/display"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/backups"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/customers"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/deployments"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/events"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// ListWazuhCCSCmd lists Wazuh MSSP customers and deployments
var ListWazuhCCSCmd = &cobra.Command{
	Use:   "wazuh-ccs",
	Short: "List Wazuh MSSP customers and deployments",
	Long: `List various aspects of the Wazuh MSSP platform:

- List all customers (default)
- List deployments (--deployments)
- List backups (--backups)
- List events (--events)
- Filter by tier (--tier)
- Filter by status (--status)`,
	RunE: eos_cli.Wrap(runListWazuhCCS),
}

func init() {
	ListCmd.AddCommand(ListWazuhCCSCmd)

	// List type flags
	ListWazuhCCSCmd.Flags().Bool("customers", true, "List customers (default)")
	ListWazuhCCSCmd.Flags().Bool("deployments", false, "List all deployments")
	ListWazuhCCSCmd.Flags().Bool("backups", false, "List customer backups")
	ListWazuhCCSCmd.Flags().Bool("events", false, "List recent events")

	// Filter flags
	ListWazuhCCSCmd.Flags().String("tier", "", "Filter by tier (starter/pro/enterprise)")
	ListWazuhCCSCmd.Flags().String("status", "", "Filter by status (active/suspended/deleted)")
	ListWazuhCCSCmd.Flags().String("customer-id", "", "Filter by specific customer")

	// Output format
	ListWazuhCCSCmd.Flags().String("output", "table", "Output format (table/json/yaml)")
	ListWazuhCCSCmd.Flags().Bool("detailed", false, "Show detailed information")
}

func runListWazuhCCS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing Wazuh MSSP information")

	// Determine what to list
	showCustomers, _ := cmd.Flags().GetBool("customers")
	showDeployments, _ := cmd.Flags().GetBool("deployments")
	showBackups, _ := cmd.Flags().GetBool("backups")
	showEvents, _ := cmd.Flags().GetBool("events")

	// Default to customers if nothing specified
	if !showDeployments && !showBackups && !showEvents {
		showCustomers = true
	}

	outputFormat, _ := cmd.Flags().GetString("output")

	switch {
	case showCustomers:
		return listWazuhCustomers(rc, cmd, outputFormat)
	case showDeployments:
		return listWazuhDeployments(rc, cmd, outputFormat)
	case showBackups:
		return listWazuhBackups(rc, cmd, outputFormat)
	case showEvents:
		return listWazuhEvents(rc, cmd, outputFormat)
	default:
		return cmd.Help()
	}
}

func listWazuhCustomers(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get filters
	tierFilter, _ := cmd.Flags().GetString("tier")
	statusFilter, _ := cmd.Flags().GetString("status")
	detailed, _ := cmd.Flags().GetBool("detailed")

	// Delegate to pkg/wazuh/customers
	opts := customers.ListOptions{
		TierFilter:   tierFilter,
		StatusFilter: statusFilter,
		Detailed:     detailed,
	}
	response, err := customers.ListCustomers(rc, opts)
	if err != nil {
		return err
	}

	// Format output
	switch format {
	case "json":
		return display.OutputJSON(logger, response)
	case "yaml":
		return display.OutputYAML(logger, response)
	default:
		if detailed {
			return customers.OutputDetailedCustomerTable(logger, response)
		}
		return customers.OutputCustomerTable(logger, response)
	}
}

func listWazuhDeployments(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	customerFilter, _ := cmd.Flags().GetString("customer-id")

	// Delegate to pkg/wazuh/deployments
	opts := deployments.ListOptions{
		CustomerFilter: customerFilter,
	}
	response, err := deployments.ListDeployments(rc, opts)
	if err != nil {
		return err
	}

	// Format output
	switch format {
	case "json":
		return display.OutputJSON(logger, response)
	case "yaml":
		return display.OutputYAML(logger, response)
	default:
		return deployments.OutputDeploymentTable(logger, response)
	}
}

func listWazuhBackups(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	customerFilter, _ := cmd.Flags().GetString("customer-id")

	// Delegate to pkg/wazuh/backups
	opts := backups.ListOptions{
		CustomerFilter: customerFilter,
	}
	response, err := backups.ListBackups(rc, opts)
	if err != nil {
		return err
	}

	// Format output
	switch format {
	case "json":
		return display.OutputJSON(logger, response)
	case "yaml":
		return display.OutputYAML(logger, response)
	default:
		return backups.OutputBackupTable(logger, response)
	}
}

func listWazuhEvents(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	customerFilter, _ := cmd.Flags().GetString("customer-id")

	// Delegate to pkg/wazuh/events
	opts := events.ListOptions{
		CustomerFilter: customerFilter,
	}
	response, err := events.ListEvents(rc, opts)
	if err != nil {
		return err
	}

	// Format output
	switch format {
	case "json":
		return display.OutputJSON(logger, response)
	case "yaml":
		return display.OutputYAML(logger, response)
	default:
		return events.OutputEventTable(logger, response)
	}
}
