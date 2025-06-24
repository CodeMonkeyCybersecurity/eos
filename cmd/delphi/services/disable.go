// cmd/delphi/services/disable.go
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

// NewDisableCmd creates the disable command
func NewDisableCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:   "disable [service-name]",
		Short: "Disable Delphi pipeline services from starting at boot",
		Long: `Disable one or more Delphi pipeline services from starting automatically at boot.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service  
- delphi-emailer: Email notification service
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

Examples:
  eos delphi services disable delphi-listener
  eos delphi services disable --all`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return DelphiServices, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Disabling Delphi services")

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

			// Disable services
			for _, service := range services {
				logger.Info("Disabling service",
					zap.String("service", service))

				// Check if service exists before trying to disable it
				if !eos_unix.ServiceExists(service) {
					logger.Warn("Service unit file not found",
						zap.String("service", service))
					logger.Info(" To install service files, check your Delphi installation or run deployment commands")
					continue
				}

				if err := eos_unix.RunSystemctlWithRetry(rc.Ctx, "disable", service, 3, 2); err != nil {
					logger.Error("Failed to disable service",
						zap.String("service", service),
						zap.Error(err))
					return fmt.Errorf("failed to disable %s: %w", service, err)
				}

				logger.Info(" Service disabled successfully",
					zap.String("service", service))
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Disable all Delphi services")
	return cmd
}
