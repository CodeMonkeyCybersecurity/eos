// cmd/delphi/services/restart.go
package services

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewRestartCmd creates the restart command
func NewRestartCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:   "restart [service-name]",
		Short: "Restart Delphi pipeline services",
		Long: `Restart one or more Delphi pipeline services.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service  
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

Examples:
  eos delphi services restart delphi-listener
  eos delphi services restart --all`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return DelphiServices, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Restarting Delphi services")

			var services []string
			if all {
				services = DelphiServices
			} else if len(args) == 0 {
				return fmt.Errorf("specify a service name or use --all")
			} else {
				// Validate service name
				service := args[0]
				valid := false
				for _, s := range DelphiServices {
					if s == service {
						valid = true
						break
					}
				}
				if !valid {
					return fmt.Errorf("invalid service: %s. Valid services: %s", service, strings.Join(DelphiServices, ", "))
				}
				services = []string{service}
			}

			// Restart services
			for _, service := range services {
				logger.Info("Restarting service",
					zap.String("service", service))

				// Check if service exists before trying to restart it
				if !eos_unix.ServiceExists(service) {
					logger.Warn("Service unit file not found",
						zap.String("service", service))
					logger.Info(" To install service files, check your Delphi installation or run deployment commands")
					continue
				}

				if err := eos_unix.RestartSystemdUnitWithRetry(rc.Ctx, service, 3, 2); err != nil {
					logger.Error("Failed to restart service",
						zap.String("service", service),
						zap.Error(err))
					return fmt.Errorf("failed to restart %s: %w", service, err)
				}

				logger.Info(" Service restarted successfully",
					zap.String("service", service))
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Restart all Delphi services")
	return cmd
}
