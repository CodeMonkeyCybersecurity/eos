// cmd/delphi/services/status.go
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

// NewStatusCmd creates the status command
func NewStatusCmd() *cobra.Command {
	var all bool
	
	cmd := &cobra.Command{
		Use:   "status [service-name]",
		Short: "Check status of Delphi pipeline services",
		Long: `Check the status of one or more Delphi pipeline services.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service  
- delphi-emailer: Email notification service
- llm-worker: LLM processing service

Examples:
  eos delphi services status delphi-listener
  eos delphi services status --all`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return DelphiServices, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("📊 Checking Delphi services status")

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

			// Check status of services
			for _, service := range services {
				logger.Info("Checking service status",
					zap.String("service", service))
				
				// Check if service exists first
				if !eos_unix.ServiceExists(service) {
					logger.Info("Service status",
						zap.String("service", service),
						zap.String("status", "⚫ not installed"),
						zap.Bool("active", false))
					continue
				}
				
				err := eos_unix.CheckServiceStatus(rc.Ctx, service)
				
				status := "🔴 inactive"
				isActive := false
				if err == nil {
					status = "🟢 active"
					isActive = true
				}
				
				logger.Info("Service status",
					zap.String("service", service),
					zap.String("status", status),
					zap.Bool("active", isActive))
				
				if err != nil {
					logger.Debug("Service status details",
						zap.String("service", service),
						zap.Error(err))
				}
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Check status of all Delphi services")
	return cmd
}