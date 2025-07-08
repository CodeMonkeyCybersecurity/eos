// cmd/read/delphi_services_logs.go
package read

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

var delphiServicesLogsCmd = &cobra.Command{
	Use:     "delphi-services-logs [service-name]",
	Aliases: []string{"delphi-logs", "pipeline-logs"},
	Short:   "View logs for Delphi pipeline services",
	Long: `View systemd journal logs for Delphi pipeline services.

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service  
- email-structurer: Email structuring service
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization

Examples:
  eos read delphi-services-logs delphi-listener
  eos read delphi-services-logs delphi-listener --follow
  eos read delphi-services-logs llm-worker --lines 100
  eos read delphi-services-logs --all
  eos read delphi-services-logs --all --lines 25`,

	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		services := []string{"delphi-listener", "delphi-agent-enricher", "email-structurer", "llm-worker", "prompt-ab-tester"}
		return services, cobra.ShellCompDirectiveNoFileComp
	},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		follow, _ := cmd.Flags().GetBool("follow")
		lines, _ := cmd.Flags().GetInt("lines")
		all, _ := cmd.Flags().GetBool("all")

		services := []string{"delphi-listener", "delphi-agent-enricher", "email-structurer", "llm-worker", "prompt-ab-tester"}

		// Handle --all flag
		if all {
			logger.Info("Viewing logs for all Delphi services",
				zap.Bool("follow", follow),
				zap.Int("lines", lines),
				zap.Strings("services", services))

			return viewAllServiceLogs(rc, &logger, lines, follow, services)
		}

		if len(args) == 0 {
			return fmt.Errorf("specify a service name or use --all flag")
		}

		// Validate service name
		service := args[0]
		valid := false
		for _, s := range services {
			if s == service {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid service: %s. Valid services: %s", service, strings.Join(services, ", "))
		}

		logger.Info("Viewing logs for service",
			zap.String("service", service),
			zap.Bool("follow", follow),
			zap.Int("lines", lines))

		// Build journalctl command
		journalArgs := []string{"-u", service}
		if lines > 0 {
			journalArgs = append(journalArgs, fmt.Sprintf("-n%d", lines))
		}
		if follow {
			journalArgs = append(journalArgs, "-f")
		}

		// Execute journalctl
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "journalctl",
			Args:    journalArgs,
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

func init() {
	delphiServicesLogsCmd.Flags().Bool("follow", false, "Follow log output")
	delphiServicesLogsCmd.Flags().Int("lines", 50, "Number of log lines to show")
	delphiServicesLogsCmd.Flags().Bool("all", false, "View logs for all Delphi services")

	ReadCmd.AddCommand(delphiServicesLogsCmd)
}

// viewAllServiceLogs displays logs for all Delphi services with pretty formatting
func viewAllServiceLogs(rc *eos_io.RuntimeContext, logger *otelzap.LoggerWithCtx, lines int, follow bool, services []string) error {
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

	for i, service := range services {
		// Service header with decorative separator
		fmt.Printf("%s%s┌─────────────────────────────────────────────────────────────────────────────────────────┐%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("%s%s│   Service: %-70s  │%s\n", colorBold, colorGreen, service, colorReset)
		fmt.Printf("%s%s│   Showing last %-60d lines  │%s\n", colorBold, colorGreen, lines, colorReset)
		fmt.Printf("%s%s└─────────────────────────────────────────────────────────────────────────────────────────┘%s\n", colorBold, colorGreen, colorReset)

		logger.Info("Fetching logs for service",
			zap.String("service", service),
			zap.Int("lines", lines),
			zap.Int("service_index", i+1),
			zap.Int("total_services", len(services)))

		// Build journalctl command for this service
		journalArgs := []string{"-u", service, "--no-pager", "--output=short-precise"}
		if lines > 0 {
			journalArgs = append(journalArgs, fmt.Sprintf("-n%d", lines))
		}

		// Execute journalctl and capture output
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "journalctl",
			Args:    journalArgs,
			Capture: true,
		})

		if err != nil {
			fmt.Printf("%s%s Failed to fetch logs for %s: %v%s\n\n", colorBold, colorRed, service, err, colorReset)
			logger.Warn("Failed to fetch logs for service",
				zap.String("service", service),
				zap.Error(err))
			continue
		}

		if strings.TrimSpace(output) == "" {
			fmt.Printf("%s%s No recent logs found for %s%s\n\n", colorBold, colorYellow, service, colorReset)
		} else {
			// Display the logs with subtle formatting
			fmt.Printf("%s", output)
			if !strings.HasSuffix(output, "\n") {
				fmt.Println()
			}
		}

		// Add separator between services (except for the last one)
		if i < len(services)-1 {
			fmt.Printf("%s%s───────────────────────────────────────────────────────────────────────────────────────────%s\n\n", colorBold, colorCyan, colorReset)
		}
	}

	// Footer
	fmt.Printf("\n%s%s═══════════════════════════════════════════════════════════════════════════════════════%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s   Completed viewing logs for %d Delphi services%s\n", colorBold, colorGreen, len(services), colorReset)
	fmt.Printf("%s%s═══════════════════════════════════════════════════════════════════════════════════════%s\n", colorBold, colorCyan, colorReset)

	logger.Info("Successfully displayed logs for all Delphi services",
		zap.Int("services_count", len(services)),
		zap.Int("lines_per_service", lines))

	return nil
}