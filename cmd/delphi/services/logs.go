// cmd/delphi/services/logs.go
package services

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewLogsCmd creates the logs command
func NewLogsCmd() *cobra.Command {
	var (
		follow bool
		lines  int
	)
	
	cmd := &cobra.Command{
		Use:   "logs [service-name]",
		Short: "View logs for Delphi pipeline services",
		Long: `View systemd journal logs for Delphi pipeline services.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service  
- delphi-emailer: Email notification service
- llm-worker: LLM processing service

Examples:
  eos delphi services logs delphi-listener
  eos delphi services logs delphi-listener --follow
  eos delphi services logs llm-worker --lines 100`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return DelphiServices, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
			if len(args) == 0 {
				return fmt.Errorf("specify a service name")
			}

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

			logger.Info("📜 Viewing logs for service",
				zap.String("service", service),
				zap.Bool("follow", follow),
				zap.Int("lines", lines))

			// Build journalctl command
			args = []string{"-u", service}
			if lines > 0 {
				args = append(args, fmt.Sprintf("-n%d", lines))
			}
			if follow {
				args = append(args, "-f")
			}

			// Execute journalctl
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "journalctl",
				Args:    args,
			})
			if err != nil {
				logger.Error("Failed to view logs",
					zap.String("service", service),
					zap.Error(err))
				return fmt.Errorf("failed to view logs for %s: %w", service, err)
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "Number of log lines to show")
	return cmd
}