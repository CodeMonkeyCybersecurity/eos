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
		all    bool
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
  eos delphi services logs llm-worker --lines 100
  eos delphi services logs --all
  eos delphi services logs --all --lines 25`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return DelphiServices, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
			// Handle --all flag
			if all {
				logger.Info("📜 Viewing logs for all Delphi services",
					zap.Bool("follow", follow),
					zap.Int("lines", lines),
					zap.Strings("services", DelphiServices))

				return viewAllServiceLogs(rc, &logger, lines, follow)
			}
			
			if len(args) == 0 {
				return fmt.Errorf("specify a service name or use --all flag")
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
	cmd.Flags().BoolVar(&all, "all", false, "View logs for all Delphi services")
	return cmd
}

// viewAllServiceLogs displays logs for all Delphi services with pretty formatting
func viewAllServiceLogs(rc *eos_io.RuntimeContext, logger *otelzap.LoggerWithCtx, lines int, follow bool) error {
	if follow {
		return fmt.Errorf("--follow flag is not supported with --all (would create multiple concurrent streams)")
	}

	// Use ANSI color codes for pretty formatting
	const (
		colorReset  = "\033[0m"
		colorBold   = "\033[1m"
		colorBlue   = "\033[34m"
		colorGreen  = "\033[32m"
		colorYellow = "\033[33m"
		colorRed    = "\033[31m"
		colorCyan   = "\033[36m"
	)

	// Header
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════════════════════════════════%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s                              DELPHI SERVICES LOGS%s\n", colorBold, colorBlue, colorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════════════════════════════════%s\n\n", colorBold, colorCyan, colorReset)

	for i, service := range DelphiServices {
		// Service header with decorative separator
		fmt.Printf("%s%s┌─────────────────────────────────────────────────────────────────────────────────────────┐%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("%s%s│  📋 Service: %-70s  │%s\n", colorBold, colorGreen, service, colorReset)
		fmt.Printf("%s%s│  📊 Showing last %-60d lines  │%s\n", colorBold, colorGreen, lines, colorReset)
		fmt.Printf("%s%s└─────────────────────────────────────────────────────────────────────────────────────────┘%s\n", colorBold, colorGreen, colorReset)

		logger.Info("📜 Fetching logs for service",
			zap.String("service", service),
			zap.Int("lines", lines),
			zap.Int("service_index", i+1),
			zap.Int("total_services", len(DelphiServices)))

		// Build journalctl command for this service
		args := []string{"-u", service, "--no-pager", "--output=short-precise"}
		if lines > 0 {
			args = append(args, fmt.Sprintf("-n%d", lines))
		}

		// Execute journalctl and capture output
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "journalctl",
			Args:    args,
			Capture: true,
		})
		
		if err != nil {
			fmt.Printf("%s%s⚠️  Failed to fetch logs for %s: %v%s\n\n", colorBold, colorRed, service, err, colorReset)
			logger.Warn("Failed to fetch logs for service",
				zap.String("service", service),
				zap.Error(err))
			continue
		}

		if strings.TrimSpace(output) == "" {
			fmt.Printf("%s%s📝 No recent logs found for %s%s\n\n", colorBold, colorYellow, service, colorReset)
		} else {
			// Display the logs with subtle formatting
			fmt.Printf("%s", output)
			if !strings.HasSuffix(output, "\n") {
				fmt.Println()
			}
		}

		// Add separator between services (except for the last one)
		if i < len(DelphiServices)-1 {
			fmt.Printf("%s%s───────────────────────────────────────────────────────────────────────────────────────────%s\n\n", colorBold, colorCyan, colorReset)
		}
	}

	// Footer
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════════════════════════════════%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s  ✅ Completed viewing logs for %d Delphi services%s\n", colorBold, colorGreen, len(DelphiServices), colorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════════════════════════════════%s\n", colorBold, colorCyan, colorReset)

	logger.Info("✅ Successfully displayed logs for all Delphi services",
		zap.Int("services_count", len(DelphiServices)),
		zap.Int("lines_per_service", lines))

	return nil
}