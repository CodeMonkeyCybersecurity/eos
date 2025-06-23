// cmd/delphi/services/enable.go
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

// NewEnableCmd creates the enable command
func NewEnableCmd() *cobra.Command {
	var all bool
	
	cmd := &cobra.Command{
		Use:   "enable [service-name]",
		Short: "Enable Delphi pipeline services to start at boot",
		Long: `Enable one or more Delphi pipeline services to start automatically at boot.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service  
- delphi-emailer: Email notification service
- llm-worker: LLM processing service

Examples:
  eos delphi services enable delphi-listener
  eos delphi services enable --all`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return DelphiServices, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("🔧 Enabling Delphi services")

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

			// Enable services
			for _, service := range services {
				logger.Info("Enabling service",
					zap.String("service", service))
				
				if err := eos_unix.RunSystemctlWithRetry(rc.Ctx, "enable", service, 3, 2); err != nil {
					logger.Error("Failed to enable service",
						zap.String("service", service),
						zap.Error(err))
					return fmt.Errorf("failed to enable %s: %w", service, err)
				}
				
				logger.Info("✅ Service enabled successfully",
					zap.String("service", service))
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Enable all Delphi services")
	return cmd
}