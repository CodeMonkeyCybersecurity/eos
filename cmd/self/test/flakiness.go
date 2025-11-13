package test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var flakinessCmd = &cobra.Command{
	Use:   "flakiness",
	Short: "Detect flaky tests by running them multiple times",
	Long: `Detects flaky tests by running them multiple times with the race detector.

A flaky test is one that sometimes passes and sometimes fails without code changes.
This command helps identify such tests before they cause issues in CI/CD.

The command:
1. Runs specified tests multiple times (default: 10)
2. Uses race detector to catch concurrency issues
3. Reports any tests that fail intermittently
4. Provides remediation guidance

Common causes of flakiness:
- Race conditions (use -race to detect)
- Timing dependencies (replace time.Sleep with polling)
- Map iteration order (sort before comparing)
- Shared global state (ensure test isolation)
- Non-deterministic random values (use fixed seeds)

Examples:
  # Test package for flakiness (10 runs)
  eos self test flakiness --package=./pkg/vault/...

  # Run tests 50 times for thorough detection
  eos self test flakiness --package=./pkg/vault/... --count=50

  # Test specific function
  eos self test flakiness --package=./pkg/vault/... --run=TestUnsealVault

  # Quick check (5 runs, no race detector)
  eos self test flakiness --package=./pkg/vault/... --count=5 --no-race
`,
	RunE: eos_cli.Wrap(runFlakiness),
}

func init() {
	flakinessCmd.Flags().String("package", "./...", "Package pattern to test")
	flakinessCmd.Flags().Int("count", 10, "Number of times to run each test")
	flakinessCmd.Flags().String("run", "", "Run only tests matching regexp")
	flakinessCmd.Flags().Bool("no-race", false, "Disable race detector (faster but less thorough)")
	flakinessCmd.Flags().Bool("verbose", false, "Show verbose test output")
	flakinessCmd.Flags().Bool("short", false, "Run tests in short mode")
}

func runFlakiness(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	packagePattern, _ := cmd.Flags().GetString("package")
	count, _ := cmd.Flags().GetInt("count")
	runPattern, _ := cmd.Flags().GetString("run")
	noRace, _ := cmd.Flags().GetBool("no-race")
	verbose, _ := cmd.Flags().GetBool("verbose")
	short, _ := cmd.Flags().GetBool("short")

	logger.Info("Detecting flaky tests",
		zap.String("package", packagePattern),
		zap.Int("count", count),
		zap.Bool("race_detector", !noRace))

	// ASSESS: Check if go is available
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go command not found: %w", err)
	}

	// INTERVENE: Run tests multiple times
	result, err := runTestsMultipleTimes(rc, flakinessConfig{
		PackagePattern:  packagePattern,
		Count:           count,
		RunPattern:      runPattern,
		UseRaceDetector: !noRace,
		Verbose:         verbose,
		Short:           short,
	})

	// EVALUATE: Report results
	return reportFlakinessResults(rc, result, err)
}

type flakinessConfig struct {
	PackagePattern  string
	Count           int
	RunPattern      string
	UseRaceDetector bool
	Verbose         bool
	Short           bool
}

type flakinessResult struct {
	TotalRuns    int
	PassedRuns   int
	FailedRuns   int
	Output       string
	Flaky        bool
	FailureLines []string
}

func runTestsMultipleTimes(rc *eos_io.RuntimeContext, config flakinessConfig) (*flakinessResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Flakiness Detection: Running %d times\n", config.Count)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Build test arguments
	args := []string{"test"}

	// Add count flag
	args = append(args, fmt.Sprintf("-count=%d", config.Count))

	// Add race detector
	if config.UseRaceDetector {
		args = append(args, "-race")
		logger.Debug("Race detector enabled")
	}

	// Add verbose flag
	if config.Verbose {
		args = append(args, "-v")
	}

	// Add short flag
	if config.Short {
		args = append(args, "-short")
	}

	// Add run pattern if specified
	if config.RunPattern != "" {
		args = append(args, fmt.Sprintf("-run=%s", config.RunPattern))
		logger.Debug("Filtering tests", zap.String("pattern", config.RunPattern))
	}

	// Add package pattern
	args = append(args, config.PackagePattern)

	logger.Info("Running tests",
		zap.String("command", "go "+strings.Join(args, " ")),
		zap.Int("count", config.Count))

	// Run tests
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "go",
		Args:    args,
		Capture: true,
	})

	result := &flakinessResult{
		TotalRuns: config.Count,
		Output:    output,
	}

	// Analyze output
	if err != nil {
		result.FailedRuns++
		result.Flaky = true
		result.FailureLines = extractFailureLines(output)
		logger.Warn("Tests failed",
			zap.Int("failed_runs", result.FailedRuns),
			zap.Int("total_runs", result.TotalRuns))
	} else {
		result.PassedRuns = config.Count
		logger.Info("All test runs passed",
			zap.Int("runs", result.PassedRuns))
	}

	return result, err
}

func extractFailureLines(output string) []string {
	var failureLines []string

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Look for FAIL lines or panic lines
		if strings.Contains(line, "FAIL") ||
			strings.Contains(line, "panic:") ||
			strings.Contains(line, "fatal error:") ||
			strings.Contains(line, "DATA RACE") {
			failureLines = append(failureLines, line)
		}
	}

	return failureLines
}

func reportFlakinessResults(rc *eos_io.RuntimeContext, result *flakinessResult, testErr error) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Flakiness Detection Results")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	if testErr == nil {
		fmt.Printf("✓ All %d test runs PASSED\n", result.TotalRuns)
		fmt.Println("\nNo flakiness detected!")
		logger.Info("No flakiness detected", zap.Int("runs", result.TotalRuns))
		return nil
	}

	// Flaky tests detected
	fmt.Printf("✗ FLAKY TESTS DETECTED\n\n")
	fmt.Printf("Total runs:  %d\n", result.TotalRuns)
	fmt.Printf("Failed runs: %d\n", result.FailedRuns)
	fmt.Printf("Passed runs: %d\n", result.PassedRuns)
	fmt.Println()

	if len(result.FailureLines) > 0 {
		fmt.Println("Failure indicators:")
		for _, line := range result.FailureLines {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()
	}

	fmt.Println("Common causes of flakiness:")
	fmt.Println("  1. Race conditions - Check 'DATA RACE' in output above")
	fmt.Println("  2. Timing dependencies - Replace time.Sleep() with polling + timeout")
	fmt.Println("  3. Map iteration order - Sort maps before comparing")
	fmt.Println("  4. Shared global state - Ensure proper test isolation with t.Cleanup()")
	fmt.Println("  5. Non-deterministic random values - Use fixed seeds (rand.Seed(42))")
	fmt.Println()

	fmt.Println("How to fix:")
	fmt.Println("  1. Review the test output above for specific failures")
	fmt.Println("  2. If 'DATA RACE' appears, fix the race condition")
	fmt.Println("  3. If timeout-related, replace time.Sleep with require.Eventually()")
	fmt.Println("  4. Add t.Parallel() carefully - it can expose hidden races")
	fmt.Println("  5. Use t.Cleanup() instead of defer for test teardown")
	fmt.Println()

	fmt.Println("Resources:")
	fmt.Println("  - Go Testing Best Practices: https://go.dev/wiki/TestComments")
	fmt.Println("  - Detecting Flakiness: https://circleci.com/blog/reducing-flaky-test-failures/")
	fmt.Println("  - Eos Integration Testing Guide: /INTEGRATION_TESTING.md")
	fmt.Println()

	// Write detailed output to file for analysis
	outputFile := "flakiness-report.txt"
	if err := os.WriteFile(outputFile, []byte(result.Output), 0644); err != nil {
		logger.Warn("Failed to write flakiness report", zap.Error(err))
	} else {
		fmt.Printf("Full test output saved to: %s\n", outputFile)
		logger.Info("Flakiness report saved", zap.String("file", outputFile))
	}

	logger.Error("Flaky tests detected",
		zap.Int("total_runs", result.TotalRuns),
		zap.Int("failed_runs", result.FailedRuns),
		zap.Strings("failure_indicators", result.FailureLines))

	return fmt.Errorf("flaky tests detected - failed %d out of %d runs", result.FailedRuns, result.TotalRuns)
}
