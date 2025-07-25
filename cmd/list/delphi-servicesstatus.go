// cmd/list/delphi-servicesstatus.go
package list

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var delphiServicesStatusCmd = &cobra.Command{
	Use:     "delphi-services-status [service-name]",
	Aliases: []string{"delphi-status", "delphi-svc-status", "delphi-services-check"},
	Short:   "Check status of Delphi pipeline services",
	Long: `Check the status of one or more Delphi pipeline services.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service  
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization
- ab-test-analyzer: A/B test analysis worker
- alert-to-db: Database operations for alerts
- email-structurer: Email structuring service
- email-formatter: Email formatting service
- email-sender: Email sending service

Examples:
  eos list delphi-services-status delphi-listener
  eos list delphi-services-status --all`,
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		// Use the DelphiServices slice for autocompletion
		return shared.GetGlobalDelphiServiceRegistry().GetActiveServiceNames(), cobra.ShellCompDirectiveNoFileComp
	},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Checking Delphi services status")

		all, _ := cmd.Flags().GetBool("all")
		var services []string
		if all {
			services = shared.GetGlobalDelphiServiceRegistry().GetActiveServiceNames()
		} else if len(args) == 0 {
			return fmt.Errorf("specify a service name or use --all")
		} else {
			// Validate service name
			service := args[0]
			valid := false
			for _, s := range shared.GetGlobalDelphiServiceRegistry().GetActiveServiceNames() {
				if s == service {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid service: %s. Valid services: %s", service, strings.Join(shared.GetGlobalDelphiServiceRegistry().GetActiveServiceNames(), ", "))
			}
			services = []string{service}
		}

		// Check status of services
		for _, service := range services {
			logger.Info("Checking service status",
				zap.String("service", service))

			// Check if service exists first
			if !eos_unix.ServiceExists(rc.Ctx, service) {
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

func init() {
	delphiServicesStatusCmd.Flags().BoolP("all", "a", false, "Check status of all Delphi services")

	ListCmd.AddCommand(delphiServicesStatusCmd)
}
