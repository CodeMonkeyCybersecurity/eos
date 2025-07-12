// cmd/delphi/services/read.go
package read

import (
	"fmt"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline/services"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	pipelineServicesShowConfig bool
)

// pipelineServicesCmd displays detailed information about a Delphi service
var pipelineServicesCmd = &cobra.Command{
	Use:   "services <service-name>",
	Short: "Display detailed information about a Delphi service",
	Long: `Display comprehensive information about a Delphi service including:
- Service status and health
- Configuration files and their existence
- Worker script details
- Systemd service configuration
- Dependencies and requirements
- Recent logs (last 10 lines)

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

Examples:
  eos read services llm-worker
  eos read services prompt-ab-tester --show-config`,
	Args: cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		configs := pipeline.GetServiceConfigurations()
		var services []string
		for name := range configs {
			services = append(services, name)
		}
		return services, cobra.ShellCompDirectiveNoFileComp
	},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		serviceName := args[0]

		logger.Info(" Reading Delphi service information",
			zap.String("service", serviceName))

		// Get service configuration
		configs := pipeline.GetServiceConfigurations()
		config, exists := configs[serviceName]
		if !exists {
			return fmt.Errorf("unknown service: %s", serviceName)
		}

		// Display basic service information
		logger.Info(" Service Information",
			zap.String("name", config.Name),
			zap.String("description", config.Description))

		// Check service status
		status, err := services.GetServiceStatus(rc, serviceName)
		if err != nil {
			logger.Warn(" Failed to get service status", zap.Error(err))
		} else {
			logger.Info(" Service Status",
				zap.String("status", status.Status),
				zap.String("active", status.Active),
				zap.String("enabled", status.Enabled),
				zap.String("uptime", status.Uptime))
		}

		// Check worker script
		workerExists := shared.FileExists(config.WorkerFile)
		workerInfo := services.GetFileInfo(rc, config.WorkerFile)
		logger.Info(" Worker Script",
			zap.String("path", config.WorkerFile),
			zap.Bool("exists", workerExists),
			zap.String("permissions", workerInfo.Permissions),
			zap.String("size", workerInfo.Size),
			zap.String("modified", workerInfo.Modified))

		// Check service file
		serviceExists := shared.FileExists(config.ServiceFile)
		serviceInfo := services.GetFileInfo(rc, config.ServiceFile)
		logger.Info(" Service File",
			zap.String("path", config.ServiceFile),
			zap.Bool("exists", serviceExists),
			zap.String("permissions", serviceInfo.Permissions),
			zap.String("size", serviceInfo.Size),
			zap.String("modified", serviceInfo.Modified))

		// Check configuration files
		logger.Info(" Configuration Files")
		for _, configFile := range config.ConfigFiles {
			configExists := shared.FileExists(configFile)
			configInfo := services.GetFileInfo(rc, configFile)
			logger.Info(" "+filepath.Base(configFile),
				zap.String("path", configFile),
				zap.Bool("exists", configExists),
				zap.String("permissions", configInfo.Permissions),
				zap.String("size", configInfo.Size))
		}

		// Display dependencies
		logger.Info(" Dependencies",
			zap.Strings("required", config.Dependencies))

		// Show recent logs
		if err := services.ShowRecentLogs(rc, serviceName); err != nil {
			logger.Warn(" Failed to retrieve recent logs", zap.Error(err))
		}

		// Show configuration content if requested
		if pipelineServicesShowConfig {
			if err := services.ShowServiceConfiguration(rc, config); err != nil {
				logger.Warn(" Failed to display configuration", zap.Error(err))
			}
		}

		return nil
	}),
}

func init() {
	pipelineServicesCmd.Flags().BoolVarP(&pipelineServicesShowConfig, "show-config", "c", false, "Display service configuration file content")
}

// All helper functions have been migrated to pkg/pipeline/services/
