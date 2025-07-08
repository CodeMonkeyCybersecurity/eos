// cmd/read/monitor-delphi.go
package read

import (
	"fmt"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewMonitorCmd creates the parser-health command
func NewMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parser-health",
		Short: "Monitor Delphi parser health and performance",
		Long: `Monitor the health and performance of the Delphi prompt-aware parsing system.

This command provides comprehensive monitoring of:
- Parser performance metrics by prompt type
- Circuit breaker status for failing parsers
- Pipeline status and throughput
- Recent parser failures and recommendations

The monitoring dashboard shows real-time insights into the parsing system
to help identify issues, optimize performance, and ensure reliable operation.`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			logger.Info(" Starting parser monitoring dashboard")

			// Check if parser-monitor.py is available
			monitorPath := "/usr/local/bin/parser-monitor.py"
			if _, err := exec.LookPath("python3"); err != nil {
				return fmt.Errorf("python3 not found: %w", err)
			}

			// Get flags
			continuous, _ := cmd.Flags().GetBool("continuous")
			health, _ := cmd.Flags().GetBool("health")
			performance, _ := cmd.Flags().GetBool("performance")
			failures, _ := cmd.Flags().GetBool("failures")
			recommendations, _ := cmd.Flags().GetBool("recommendations")
			circuitBreaker, _ := cmd.Flags().GetBool("circuit-breaker")
			interval, _ := cmd.Flags().GetInt("interval")

			// Build command arguments
			var cmdArgs []string
			cmdArgs = append(cmdArgs, monitorPath)

			if continuous {
				cmdArgs = append(cmdArgs, "--continuous")
				if interval != 30 {
					cmdArgs = append(cmdArgs, "--interval", fmt.Sprintf("%d", interval))
				}
			} else if health {
				cmdArgs = append(cmdArgs, "--health")
			} else if performance {
				cmdArgs = append(cmdArgs, "--performance")
			} else if failures {
				cmdArgs = append(cmdArgs, "--failures")
			} else if recommendations {
				cmdArgs = append(cmdArgs, "--recommendations")
			} else if circuitBreaker {
				cmdArgs = append(cmdArgs, "--circuit-breaker")
			}
			// If no flags, run default dashboard

			logger.Info(" Executing parser monitor",
				zap.String("command", strings.Join(cmdArgs, " ")))

			// Execute the monitoring script
			monitorCmd := exec.CommandContext(rc.Ctx, "python3", cmdArgs...)
			monitorCmd.Stdout = cmd.OutOrStdout()
			monitorCmd.Stderr = cmd.ErrOrStderr()

			if err := monitorCmd.Run(); err != nil {
				return fmt.Errorf("parser monitor failed: %w", err)
			}

			logger.Info(" Parser monitoring completed")
			return nil
		}),
	}

	// Add flags
	cmd.Flags().BoolP("continuous", "c", false, "Run continuously with live updates")
	cmd.Flags().Int("interval", 30, "Refresh interval in seconds for continuous mode")
	cmd.Flags().Bool("health", false, "Show health summary only")
	cmd.Flags().Bool("performance", false, "Show detailed parser performance metrics")
	cmd.Flags().Bool("failures", false, "Show recent parser failures")
	cmd.Flags().Bool("recommendations", false, "Show parser optimization recommendations")
	cmd.Flags().Bool("circuit-breaker", false, "Show circuit breaker status")

	return cmd
}