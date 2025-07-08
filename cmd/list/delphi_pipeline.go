// cmd/list/delphi_services.go
package list

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var delphiServicesCmd = &cobra.Command{
	Use:     "delphi-services",
	Aliases: []string{"delphi-svc", "wazuh-services"},
	Short:   "List all Delphi (Wazuh) services and their status",
	Long: `List all available Delphi services with their current status.

Shows for each service:
- Name and description
- Current status (active/inactive)
- Enabled status (enabled/disabled)
- File existence (worker script and service file)

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- delphi-alert-processor: Alert processing and correlation
- delphi-log-shipper: Log shipping and forwarding
- delphi-metrics-collector: Metrics collection service

Examples:
  eos list delphi-services                     # List all services
  eos list delphi-services --detailed         # Show detailed information
  eos list delphi-services --status active    # Show only active services`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse flags
		detailed, _ := cmd.Flags().GetBool("detailed")
		statusFilter, _ := cmd.Flags().GetString("status")

		logger.Info("Listing Delphi services",
			zap.Bool("detailed", detailed),
			zap.String("status_filter", statusFilter))

		// Get service information using shared registry
		services := shared.GetGlobalDelphiServiceRegistry().GetActiveServices()

		// Apply status filter if specified
		if statusFilter != "" && statusFilter != "all" {
			services = filterServicesByStatus(services, statusFilter).(map[string]shared.DelphiServiceDefinition)
		}

		// Display services
		return displayServicesTable(services, detailed)
	}),
}

func init() {
	delphiServicesCmd.Flags().Bool("detailed", false, "Show detailed service information")
	delphiServicesCmd.Flags().String("status", "all", "Filter by status: all, active, inactive, enabled, disabled")

	ListCmd.AddCommand(delphiServicesCmd)
}

func filterServicesByStatus(services interface{}, status string) interface{} {
	// TODO: Implement filtering based on actual service structure
	// For now, just return the services as-is
	return services
}

func displayServicesTable(services interface{}, detailed bool) error {
	// TODO: Implement service table display based on actual service structure
	// This would typically iterate through services and format them nicely
	return nil
}
