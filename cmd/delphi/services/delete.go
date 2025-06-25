// cmd/delphi/services/delete.go
package services

import (
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewDeleteCmd creates the delete command
func NewDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete <service-name>",
		Short: "Remove a Delphi service and its files",
		Long: `Remove a Delphi service including:
1. Stop the service if running
2. Disable the service from auto-start
3. Remove the systemd service file
4. Remove the worker script
5. Reload systemd daemon

This does NOT remove configuration files or data, only the service installation.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- delphi-emailer: Email notification service
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

Examples:
  eos delphi services delete llm-worker
  eos delphi services delete prompt-ab-tester --force`,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			configs := GetServiceConfigurations()
			var services []string
			for name := range configs {
				services = append(services, name)
			}
			return services, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			serviceName := args[0]

			logger.Info("🗑️ Deleting Delphi service",
				zap.String("service", serviceName))

			// Check if running as root
			if !eos_unix.IsPrivilegedUser(rc.Ctx) {
				return fmt.Errorf("service deletion requires root privileges")
			}

			// Get service configuration
			configs := GetServiceConfigurations()
			config, exists := configs[serviceName]
			if !exists {
				return fmt.Errorf("unknown service: %s", serviceName)
			}

			// Check if service exists
			if !eos_unix.ServiceExists(serviceName) {
				logger.Warn(" Service not found in systemd",
					zap.String("service", serviceName))
			} else {
				// Stop the service if running
				status, err := getServiceStatus(rc, serviceName)
				if err == nil && status.Active == "active" {
					logger.Info(" Stopping service",
						zap.String("service", serviceName))
					
					if err := eos_unix.StopSystemdUnitWithRetry(rc.Ctx, serviceName, 3, 2); err != nil {
						if !force {
							return fmt.Errorf("failed to stop service %s (use --force to ignore): %w", serviceName, err)
						}
						logger.Warn(" Failed to stop service, continuing due to --force flag",
							zap.String("service", serviceName),
							zap.Error(err))
					} else {
						logger.Info(" Service stopped successfully",
							zap.String("service", serviceName))
					}
				}

				// Disable the service
				logger.Info(" Disabling service",
					zap.String("service", serviceName))
				
				if err := exec.Command("systemctl", "disable", serviceName).Run(); err != nil {
					if !force {
						return fmt.Errorf("failed to disable service %s (use --force to ignore): %w", serviceName, err)
					}
					logger.Warn(" Failed to disable service, continuing due to --force flag",
						zap.String("service", serviceName),
						zap.Error(err))
				} else {
					logger.Info(" Service disabled successfully",
						zap.String("service", serviceName))
				}
			}

			// Remove service file
			if eos_unix.FileExists(config.ServiceFile) {
				logger.Info(" Removing service file",
					zap.String("file", config.ServiceFile))
				
				if err := os.Remove(config.ServiceFile); err != nil {
					if !force {
						return fmt.Errorf("failed to remove service file %s (use --force to ignore): %w", config.ServiceFile, err)
					}
					logger.Warn(" Failed to remove service file, continuing due to --force flag",
						zap.String("file", config.ServiceFile),
						zap.Error(err))
				} else {
					logger.Info(" Service file removed successfully",
						zap.String("file", config.ServiceFile))
				}
			} else {
				logger.Info(" Service file not found (already removed)",
					zap.String("file", config.ServiceFile))
			}

			// Remove worker script
			if eos_unix.FileExists(config.WorkerFile) {
				logger.Info(" Removing worker script",
					zap.String("file", config.WorkerFile))
				
				if err := os.Remove(config.WorkerFile); err != nil {
					if !force {
						return fmt.Errorf("failed to remove worker script %s (use --force to ignore): %w", config.WorkerFile, err)
					}
					logger.Warn(" Failed to remove worker script, continuing due to --force flag",
						zap.String("file", config.WorkerFile),
						zap.Error(err))
				} else {
					logger.Info(" Worker script removed successfully",
						zap.String("file", config.WorkerFile))
				}
			} else {
				logger.Info(" Worker script not found (already removed)",
					zap.String("file", config.WorkerFile))
			}

			// Reload systemd daemon
			logger.Info(" Reloading systemd daemon")
			if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
				logger.Warn(" Failed to reload systemd daemon", zap.Error(err))
			} else {
				logger.Info(" Systemd daemon reloaded")
			}

			logger.Info("✨ Service deleted successfully",
				zap.String("service", serviceName),
				zap.String("description", config.Description))

			logger.Info(" Note: Configuration files and data were preserved",
				zap.Strings("config_files", config.ConfigFiles))

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force deletion even if stop/disable operations fail")
	return cmd
}