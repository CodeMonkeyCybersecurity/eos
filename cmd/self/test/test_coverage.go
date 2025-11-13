package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var testCoverageCmd = &cobra.Command{
	Use:   "coverage",
	Short: "Generate and analyze test coverage reports",
	Long: `Generates test coverage reports and checks against configured thresholds.

This command:
1. Runs tests with coverage profiling
2. Generates coverage reports (text, HTML, or both)
3. Checks coverage against thresholds from .testcoverage.yml
4. Optionally opens HTML report in browser

Examples:
  # Generate text coverage report
  eos self test coverage

  # Generate HTML report and open in browser
  eos self test coverage --html --open

  # Check coverage for specific package
  eos self test coverage --package=./pkg/vault/...

  # Skip threshold checks (just generate report)
  eos self test coverage --no-threshold-check
`,
	RunE: eos_cli.Wrap(runCoverage),
}

func init() {
	testCoverageCmd.Flags().Bool("html", false, "Generate HTML coverage report")
	testCoverageCmd.Flags().Bool("open", false, "Open HTML report in browser (implies --html)")
	testCoverageCmd.Flags().String("package", "./...", "Package pattern to test")
	testCoverageCmd.Flags().Bool("no-threshold-check", false, "Skip threshold validation")
	testCoverageCmd.Flags().String("output", "coverage.out", "Coverage profile output file")
}

func runCoverage(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	htmlReport, _ := cmd.Flags().GetBool("html")
	openBrowser, _ := cmd.Flags().GetBool("open")
	packagePattern, _ := cmd.Flags().GetString("package")
	noThresholdCheck, _ := cmd.Flags().GetBool("no-threshold-check")
	outputFile, _ := cmd.Flags().GetString("output")

	// If --open is set, imply --html
	if openBrowser {
		htmlReport = true
	}

	logger.Info("Generating test coverage report",
		zap.String("package", packagePattern),
		zap.String("output", outputFile),
		zap.Bool("html", htmlReport))

	// ASSESS: Check if coverage tools are available
	if err := checkCoverageTools(rc, noThresholdCheck); err != nil {
		return err
	}

	// INTERVENE: Generate coverage profile
	if err := generateCoverageProfile(rc, packagePattern, outputFile); err != nil {
		return err
	}

	// Generate HTML report if requested
	if htmlReport {
		htmlFile := strings.TrimSuffix(outputFile, ".out") + ".html"
		if err := generateHTMLReport(rc, outputFile, htmlFile); err != nil {
			return err
		}

		if openBrowser {
			if err := openHTMLInBrowser(rc, htmlFile); err != nil {
				logger.Warn("Failed to open browser", zap.Error(err))
				fmt.Printf("\nHTML report generated: %s\n", htmlFile)
				fmt.Printf("Open it manually in your browser.\n")
			} else {
				logger.Info("Opened HTML report in browser", zap.String("file", htmlFile))
			}
		} else {
			fmt.Printf("\nHTML report generated: %s\n", htmlFile)
		}
	}

	// Generate text summary
	if err := displayCoverageSummary(rc, outputFile); err != nil {
		logger.Warn("Failed to display coverage summary", zap.Error(err))
	}

	// EVALUATE: Check coverage thresholds
	if !noThresholdCheck {
		if err := checkCoverageThresholds(rc, outputFile); err != nil {
			return err
		}
	}

	logger.Info("Coverage analysis complete",
		zap.String("profile", outputFile),
		zap.Bool("threshold_checked", !noThresholdCheck))

	return nil
}

func checkCoverageTools(rc *eos_io.RuntimeContext, skipThresholdCheck bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if go is available
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go command not found - cannot generate coverage: %w", err)
	}

	// Check if go-test-coverage is available (only if we need threshold checks)
	if !skipThresholdCheck {
		if _, err := exec.LookPath("go-test-coverage"); err != nil {
			logger.Warn("go-test-coverage not found - threshold checks will be skipped",
				zap.String("install_command", "go install github.com/vladopajic/go-test-coverage/v2@latest"))
			fmt.Println("\n⚠ go-test-coverage not found - threshold checks disabled")
			fmt.Println("Install with: go install github.com/vladopajic/go-test-coverage/v2@latest")
			fmt.Println()
		}
	}

	return nil
}

func generateCoverageProfile(rc *eos_io.RuntimeContext, packagePattern, outputFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Running tests with coverage profiling",
		zap.String("package", packagePattern))

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Generating Coverage Profile")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "go",
		Args: []string{
			"test",
			"-coverprofile=" + outputFile,
			"-covermode=atomic",
			packagePattern,
		},
		Capture: true,
	})

	if err != nil {
		logger.Error("Coverage generation failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("failed to generate coverage profile: %s\n%w", output, err)
	}

	// Print test output
	fmt.Print(output)

	logger.Info("Coverage profile generated", zap.String("file", outputFile))
	return nil
}

func generateHTMLReport(rc *eos_io.RuntimeContext, profileFile, htmlFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating HTML coverage report",
		zap.String("input", profileFile),
		zap.String("output", htmlFile))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "go",
		Args: []string{
			"tool",
			"cover",
			"-html=" + profileFile,
			"-o", htmlFile,
		},
		Capture: true,
	})

	if err != nil {
		logger.Error("HTML generation failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("failed to generate HTML report: %s\n%w", output, err)
	}

	logger.Info("HTML report generated", zap.String("file", htmlFile))
	return nil
}

func openHTMLInBrowser(rc *eos_io.RuntimeContext, htmlFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get absolute path
	absPath, err := filepath.Abs(htmlFile)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Try xdg-open (Linux), open (macOS), or start (Windows)
	var cmd string
	if _, err := exec.LookPath("xdg-open"); err == nil {
		cmd = "xdg-open"
	} else if _, err := exec.LookPath("open"); err == nil {
		cmd = "open"
	} else if _, err := exec.LookPath("start"); err == nil {
		cmd = "start"
	} else {
		return fmt.Errorf("no browser opener found (xdg-open, open, or start)")
	}

	logger.Debug("Opening HTML in browser",
		zap.String("command", cmd),
		zap.String("file", absPath))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: cmd,
		Args:    []string{absPath},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to open browser: %s\n%w", output, err)
	}

	return nil
}

func displayCoverageSummary(rc *eos_io.RuntimeContext, profileFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Displaying coverage summary")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "go",
		Args: []string{
			"tool",
			"cover",
			"-func=" + profileFile,
		},
		Capture: true,
	})

	if err != nil {
		logger.Error("Failed to generate coverage summary",
			zap.Error(err))
		return fmt.Errorf("failed to generate summary: %w", err)
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Coverage Summary")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Print(output)

	return nil
}

func checkCoverageThresholds(rc *eos_io.RuntimeContext, profileFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if .testcoverage.yml exists
	if _, err := os.Stat(".testcoverage.yml"); os.IsNotExist(err) {
		logger.Warn("No .testcoverage.yml found - skipping threshold checks",
			zap.String("remediation", "Create .testcoverage.yml to enforce coverage thresholds"))
		fmt.Println("\n⚠ No .testcoverage.yml found - threshold checks skipped")
		return nil
	}

	// Check if go-test-coverage is available
	if _, err := exec.LookPath("go-test-coverage"); err != nil {
		logger.Warn("go-test-coverage not found - skipping threshold checks")
		fmt.Println("\n⚠ go-test-coverage not found - threshold checks skipped")
		return nil
	}

	logger.Info("Checking coverage thresholds")

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Coverage Threshold Check")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "go-test-coverage",
		Args: []string{
			"--config=.testcoverage.yml",
		},
		Capture: true,
	})

	// go-test-coverage exits with non-zero if thresholds not met
	if err != nil {
		logger.Error("Coverage thresholds not met",
			zap.Error(err),
			zap.String("output", output))
		fmt.Print(output)
		fmt.Println("\n✗ Coverage thresholds not met")
		fmt.Println("\nRemediation:")
		fmt.Println("  1. Add tests to increase coverage")
		fmt.Println("  2. Or update thresholds in .testcoverage.yml if current coverage is acceptable")
		return fmt.Errorf("coverage below thresholds")
	}

	fmt.Print(output)
	fmt.Println("\n✓ All coverage thresholds met!")

	return nil
}
