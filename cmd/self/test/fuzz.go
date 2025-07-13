// cmd/test/fuzz.go
package test

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testing"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Run fuzz tests",
	Long: `Execute all fuzz tests across the Eos codebase.
	
This command runs comprehensive fuzz testing on critical security-related
functions throughout the Eos project, including crypto operations, input
validation, command parsing, and more.

Fuzz testing helps identify:
- Crash-inducing inputs
- Memory safety violations
- Input validation bypasses
- Unexpected behavior in edge cases

Examples:
  # Run fuzz tests with default settings (10s per test)
  eos self test fuzz
  
  # Run fuzz tests for 1 minute each
  eos self test fuzz --duration 1m
  
  # Run with higher parallelism
  eos self test fuzz --parallel 8
  
  # Save detailed report
  eos self test fuzz --duration 5m --report-file fuzz-report.json`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		duration, err := time.ParseDuration(fuzzDuration)
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}

		runner, err := testing.NewFuzzRunner(rc)
		if err != nil {
			return fmt.Errorf("failed to create fuzz runner: %w", err)
		}

		// Set parallelism
		runner.SetParallelism(fuzzParallel)

		logger.Info("Starting fuzz test execution",
			zap.Duration("duration", duration),
			zap.Int("parallel", fuzzParallel))

		logger.Info("terminal prompt: 🧪 Running fuzz tests with %s duration...", duration)
		logger.Info("terminal prompt: 📍 Parallel execution: %d tests", fuzzParallel)
		logger.Info("terminal prompt:  Working directory: %s\n", rc.Ctx.Value("workdir"))

		report, err := runner.RunAll(duration)
		if err != nil {
			return fmt.Errorf("fuzz tests failed: %w", err)
		}

		// Display summary
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", report.Summary())))

		// Save detailed report if requested
		if reportFile != "" {
			if err := report.SaveReport(reportFile); err != nil {
				logger.Warn("Failed to save report file",
					zap.String("file", reportFile),
					zap.Error(err))
			} else {
				logger.Info("terminal prompt: \n📊 Detailed report saved to: %s", reportFile)
			}
		}

		// Exit with error if any tests failed
		for _, test := range report.Tests {
			if !test.Success {
				logger.Error("Some fuzz tests failed",
					zap.Int("failed_tests", countFailedTests(report.Tests)),
					zap.Duration("total_duration", report.Duration))
				return fmt.Errorf("some fuzz tests failed")
			}
		}

		logger.Info("All fuzz tests completed successfully",
			zap.Int("total_tests", len(report.Tests)),
			zap.Duration("total_duration", report.Duration))

		logger.Info("terminal prompt: \nAll fuzz tests completed successfully!")
		logger.Info("terminal prompt: 🎯 No issues found during fuzzing with %s duration.", duration)

		return nil
	}),
}

var (
	fuzzDuration string
	fuzzParallel int
	reportFile   string
)

func init() {
	TestCmd.AddCommand(fuzzCmd)

	fuzzCmd.Flags().StringVarP(&fuzzDuration, "duration", "d", "10s",
		"Duration for each fuzz test (e.g., 10s, 1m, 5m)")
	fuzzCmd.Flags().IntVarP(&fuzzParallel, "parallel", "p", 4,
		"Number of parallel fuzz tests to run")
	fuzzCmd.Flags().StringVarP(&reportFile, "report-file", "r", "",
		"Save detailed report to file")
}

// countFailedTests counts the number of failed tests
func countFailedTests(tests []testing.FuzzResult) int {
	count := 0
	for _, test := range tests {
		if !test.Success {
			count++
		}
	}
	return count
}
