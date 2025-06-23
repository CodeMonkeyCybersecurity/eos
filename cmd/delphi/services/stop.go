// cmd/delphi/services/stop.go
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

// NewStopCmd creates the stop command
func NewStopCmd() *cobra.Command {
	var all bool
	
	cmd := &cobra.Command{
		Use:   "stop [service-name]",
		Short: "Stop Delphi pipeline services",
		Long: `Stop one or more Delphi pipeline services.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service  
- delphi-emailer: Email notification service
- llm-worker: LLM processing service

Examples:
  eos delphi services stop delphi-listener
  eos delphi services stop --all`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return DelphiServices, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("🛑 Stopping Delphi services")

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

			// Stop services
			for _, service := range services {
				logger.Info("Stopping service",
					zap.String("service", service))
				
				if err := eos_unix.StopSystemdUnitWithRetry(rc.Ctx, service, 3, 2); err != nil {
					logger.Error("Failed to stop service",
						zap.String("service", service),
						zap.Error(err))
					return fmt.Errorf("failed to stop %s: %w", service, err)
				}
				
				logger.Info("✅ Service stopped successfully",
					zap.String("service", service))
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Stop all Delphi services")
	return cmd
}