package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	integrationPattern  string
	integrationVerbose  bool
	integrationTimeout  string
	integrationCoverage bool
)

// integrationCmd represents the integration test command
var integrationCmd = &cobra.Command{
	Use:   "integration [pattern]",
	Short: "Run integration tests",
	Long: `Run integration tests for the Eos codebase.

Integration tests verify the interaction between multiple components
and test real-world scenarios. These tests may require additional
setup or permissions.

Examples:
  # Run all integration tests
  eos self test integration

  # Run specific integration test
  eos self test integration TestSecretGeneration

  # Run with verbose output
  eos self test integration -v

  # Run with custom timeout
  eos self test integration --timeout 10m

  # Run with coverage
  eos self test integration --coverage`,
	RunE: eos.Wrap(runIntegrationTests),
}

func init() {
	TestCmd.AddCommand(integrationCmd)

	integrationCmd.Flags().StringVarP(&integrationPattern, "pattern", "p", "", "Test pattern to run (e.g., TestSecretGeneration)")
	integrationCmd.Flags().BoolVarP(&integrationVerbose, "verbose", "v", true, "Enable verbose output")
	integrationCmd.Flags().StringVar(&integrationTimeout, "timeout", "5m", "Test timeout duration")
	integrationCmd.Flags().BoolVar(&integrationCoverage, "coverage", false, "Generate coverage report")
}

func runIntegrationTests(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if integration tests exist
	logger.Info("Checking for integration tests")

	// Find the project root
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Look for integration test files
	integrationTestFiles := []string{
		filepath.Join(workDir, "integration_test.go"),
		filepath.Join(workDir, "integration_security_test.go"),
		filepath.Join(workDir, "integration_scenarios_test.go"),
	}

	foundTests := false
	for _, testFile := range integrationTestFiles {
		if _, err := os.Stat(testFile); err == nil {
			foundTests = true
			logger.Debug("Found integration test file", zap.String("file", testFile))
		}
	}

	if !foundTests {
		return fmt.Errorf("no integration test files found in %s", workDir)
	}

	// Build test command
	args = []string{"test"}

	if integrationVerbose {
		args = append(args, "-v")
	}

	args = append(args, "-tags=integration")
	args = append(args, fmt.Sprintf("-timeout=%s", integrationTimeout))

	if integrationCoverage {
		coverFile := filepath.Join(workDir, "coverage-integration.out")
		args = append(args, "-coverprofile="+coverFile)
		args = append(args, "-covermode=atomic")
	}

	// Add test pattern if provided
	if integrationPattern != "" {
		args = append(args, "-run", integrationPattern)
	} else if len(cmd.Flags().Args()) > 0 {
		// Support pattern as positional argument
		args = append(args, "-run", cmd.Flags().Args()[0])
	}

	// Add test files or directories
	args = append(args, "./...")

	// INTERVENE - Run the tests
	logger.Info("Running integration tests",
		zap.Strings("args", args),
		zap.String("timeout", integrationTimeout),
		zap.Bool("coverage", integrationCoverage))

	// Set environment variables for better test output
	testCmd := exec.CommandContext(rc.Ctx, "go", args...)
	testCmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",   // Some tests may need CGO
		"LOG_LEVEL=DEBUG", // Enable debug logging for tests
	)
	testCmd.Stdout = os.Stdout
	testCmd.Stderr = os.Stderr
	testCmd.Dir = workDir

	// Log the exact command being run
	logger.Info("terminal prompt: Running integration tests",
		zap.String("command", strings.Join(append([]string{"go"}, args...), " ")))

	err = testCmd.Run()

	// EVALUATE - Check results
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Test failures return exit code 1
			if exitErr.ExitCode() == 1 {
				logger.Warn("Integration tests failed", zap.Error(err))
				return fmt.Errorf("integration tests failed")
			}
		}
		return fmt.Errorf("failed to run integration tests: %w", err)
	}

	logger.Info("Integration tests completed successfully")

	// Generate coverage report if requested
	if integrationCoverage {
		coverFile := filepath.Join(workDir, "coverage-integration.out")
		htmlFile := filepath.Join(workDir, "coverage-integration.html")

		logger.Info("Generating coverage report",
			zap.String("output", htmlFile))

		coverCmd := exec.CommandContext(rc.Ctx, "go", "tool", "cover",
			"-html="+coverFile, "-o", htmlFile)
		coverCmd.Dir = workDir

		if err := coverCmd.Run(); err != nil {
			logger.Warn("Failed to generate HTML coverage report", zap.Error(err))
		} else {
			logger.Info("Coverage report generated", zap.String("file", htmlFile))
		}
	}

	return nil
}
