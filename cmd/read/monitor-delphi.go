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
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	parserHealthContinuous      bool
	parserHealthHealth          bool
	parserHealthPerformance     bool
	parserHealthFailures        bool
	parserHealthRecommendations bool
	parserHealthCircuitBreaker  bool
	parserHealthInterval        int
)

// parserHealthCmd monitors Delphi parser health and performance
var parserHealthCmd = &cobra.Command{
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

		// Build command arguments
		var cmdArgs []string
		cmdArgs = append(cmdArgs, monitorPath)

		if parserHealthContinuous {
			cmdArgs = append(cmdArgs, "--continuous")
			if parserHealthInterval != 30 {
				cmdArgs = append(cmdArgs, "--interval", fmt.Sprintf("%d", parserHealthInterval))
			}
		} else if parserHealthHealth {
			cmdArgs = append(cmdArgs, "--health")
		} else if parserHealthPerformance {
			cmdArgs = append(cmdArgs, "--performance")
		} else if parserHealthFailures {
			cmdArgs = append(cmdArgs, "--failures")
		} else if parserHealthRecommendations {
			cmdArgs = append(cmdArgs, "--recommendations")
		} else if parserHealthCircuitBreaker {
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

func init() {
	// Add flags
	parserHealthCmd.Flags().BoolVarP(&parserHealthContinuous, "continuous", "c", false, "Run continuously with live updates")
	parserHealthCmd.Flags().IntVar(&parserHealthInterval, "interval", 30, "Refresh interval in seconds for continuous mode")
	parserHealthCmd.Flags().BoolVar(&parserHealthHealth, "health", false, "Show health summary only")
	parserHealthCmd.Flags().BoolVar(&parserHealthPerformance, "performance", false, "Show detailed parser performance metrics")
	parserHealthCmd.Flags().BoolVar(&parserHealthFailures, "failures", false, "Show recent parser failures")
	parserHealthCmd.Flags().BoolVar(&parserHealthRecommendations, "recommendations", false, "Show parser optimization recommendations")
	parserHealthCmd.Flags().BoolVar(&parserHealthCircuitBreaker, "circuit-breaker", false, "Show circuit breaker status")
}