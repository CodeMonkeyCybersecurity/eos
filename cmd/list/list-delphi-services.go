// cmd/list/list-delphi-services.go
package list

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)
// TODO
// ServiceStatus represents the status of a service
type ServiceStatus struct {
	Active  string
	Enabled string
}
// TODO
// getServiceStatus returns the status of a service
func getServiceStatus(rc *eos_io.RuntimeContext, serviceName string) (ServiceStatus, error) {
	var status ServiceStatus

	// Check if service is active
	if eos_unix.ServiceExists(serviceName) {
		if err := eos_unix.CheckServiceStatus(rc.Ctx, serviceName); err == nil {
			status.Active = "active"
		} else {
			status.Active = "inactive"
		}
	} else {
		status.Active = "not-installed"
	}

	// Check if service is enabled (simplified check)
	if status.Active == "active" {
		status.Enabled = "enabled"
	} else {
		status.Enabled = "disabled"
	}

	return status, nil
}

var delphiServicesListCmd = &cobra.Command{
	Use:   "delphi-services-list",
	Aliases: []string{"delphi-services", "list-delphi-services"},
	Short: "List all Delphi services and their status",
	Long: `List all available Delphi services with their current status.

Shows for each service:
- Name and description
- Current status (active/inactive)
- Enabled status (enabled/disabled)
- File existence (worker script and service file)

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

Examples:
  eos list delphi-services-list
  eos list delphi-services-list --detailed`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Listing Delphi services")

		detailed, _ := cmd.Flags().GetBool("detailed")

		// Get all service configurations
		configs := shared.GetGlobalDelphiServiceRegistry().GetActiveServices()

		// Count totals
		var totalServices, activeServices, enabledServices, installedServices int
		totalServices = len(configs)

		logger.Info(" Service Overview")
		for serviceName, config := range configs {
			// Get service status
			status, err := getServiceStatus(rc, serviceName)
			if err != nil {
				logger.Warn(" Failed to get status for service",
					zap.String("service", serviceName),
					zap.Error(err))
				continue
			}

			// Check if files exist
			workerExists := eos_unix.FileExists(config.WorkerScript)
			serviceExists := eos_unix.FileExists(config.ServiceFile)
			isInstalled := workerExists && serviceExists

			if isInstalled {
				installedServices++
			}
			if status.Active == "active" {
				activeServices++
			}
			if status.Enabled == "enabled" {
				enabledServices++
			}

			// Display service information
			if detailed {
				logger.Info(" "+serviceName,
					zap.String("description", config.Description),
					zap.String("status", status.Active),
					zap.String("enabled", status.Enabled),
					zap.Bool("worker_exists", workerExists),
					zap.Bool("service_exists", serviceExists),
					zap.String("worker_path", config.WorkerScript),
					zap.String("service_path", config.ServiceFile))
			} else {
				statusIcon := ""
				if status.Active == "active" {
					statusIcon = ""
				} else if status.Active == "failed" {
					statusIcon = "🔥"
				} else if isInstalled {
					statusIcon = ""
				}

				enabledIcon := ""
				if status.Enabled == "enabled" {
					enabledIcon = " (auto-start)"
				}

				installStatus := ""
				if !isInstalled {
					installStatus = " [NOT INSTALLED]"
				}

				logger.Info(" "+statusIcon+" "+serviceName+enabledIcon+installStatus,
					zap.String("description", config.Description),
					zap.String("status", status.Active))
			}
		}

		// Display summary
		logger.Info(" Summary",
			zap.Int("total_services", totalServices),
			zap.Int("installed", installedServices),
			zap.Int("active", activeServices),
			zap.Int("enabled", enabledServices))

		// Show helpful commands
		if installedServices < totalServices {
			logger.Info(" Services can be created with:",
				zap.String("example", "eos delphi services create <service-name>"))
		}

		if installedServices > activeServices {
			logger.Info(" Inactive services can be started with:",
				zap.String("example", "eos delphi services start <service-name>"))
		}

		return nil
	}),
}

func init() {
	delphiServicesListCmd.Flags().BoolP("detailed", "d", false, "Show detailed information including file paths")

	ListCmd.AddCommand(delphiServicesListCmd)
}
