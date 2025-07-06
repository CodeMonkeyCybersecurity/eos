// pkg/testing/fuzz_runner.go
package testing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FuzzTest represents a single fuzz test
type FuzzTest struct {
	Name     string
	Package  string
	Function string
	Duration time.Duration
}

// FuzzRunner manages fuzz test execution
type FuzzRunner struct {
	rc          *eos_io.RuntimeContext
	logger      otelzap.LoggerWithCtx
	projectRoot string
	parallel    int
}

// FuzzResult contains results from a fuzz test run
type FuzzResult struct {
	Test     FuzzTest
	Success  bool
	Duration time.Duration
	Output   string
	Error    error
	Crashes  int
	Coverage float64
}

// FuzzReport contains the complete fuzz test report
type FuzzReport struct {
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Tests     []FuzzResult
}

// NewFuzzRunner creates a new fuzz test runner
func NewFuzzRunner(rc *eos_io.RuntimeContext) (*FuzzRunner, error) {
	// Find project root by looking for go.mod
	root, err := findProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to find project root: %w", err)
	}

	return &FuzzRunner{
		rc:          rc,
		logger:      otelzap.Ctx(rc.Ctx),
		projectRoot: root,
		parallel:    4, // Default parallelism
	}, nil
}

// findProjectRoot locates the project root directory
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

// DiscoverFuzzTests finds all fuzz tests in the project
func (fr *FuzzRunner) DiscoverFuzzTests() ([]FuzzTest, error) {
	_, span := telemetry.Start(fr.rc.Ctx, "testing.DiscoverFuzzTests")
	defer span.End()

	fr.logger.Info("Discovering fuzz tests")

	var tests []FuzzTest

	// Define packages and their fuzz tests based on the original script
	testDefs := []struct {
		pkg   string
		funcs []string
	}{
		{
			pkg: "./pkg/crypto",
			funcs: []string{
				"FuzzValidateStrongPassword",
				"FuzzHashString",
				"FuzzHashStrings",
				"FuzzAllUnique",
				"FuzzAllHashesPresent",
				"FuzzRedact",
				"FuzzInjectSecretsFromPlaceholders",
				"FuzzSecureZero",
			},
		},
		{
			pkg: "./pkg/interaction",
			funcs: []string{
				"FuzzNormalizeYesNoInput",
				"FuzzValidateNonEmpty",
				"FuzzValidateUsername",
				"FuzzValidateEmail",
				"FuzzValidateURL",
				"FuzzValidateIP",
				"FuzzValidateNoShellMeta",
			},
		},
		{
			pkg: "./pkg/parse",
			funcs: []string{
				"FuzzSplitAndTrim",
			},
		},
		{
			pkg: "./pkg/eos_cli",
			funcs: []string{
				"FuzzCommandParsing",
			},
		},
		{
			pkg: "./cmd/delphi/services",
			funcs: []string{
				"FuzzUpdateCommand",
				"FuzzServiceWorkerPaths",
				"FuzzFileOperations",
			},
		},
		{
			pkg: "./test",
			funcs: []string{
				"FuzzAllEosCommands",
				"FuzzEosCommandFlags",
				"FuzzDelphiServicesCommands",
			},
		},
	}

	for _, def := range testDefs {
		for _, fn := range def.funcs {
			tests = append(tests, FuzzTest{
				Name:     fmt.Sprintf("%s.%s", def.pkg, fn),
				Package:  def.pkg,
				Function: fn,
				Duration: 10 * time.Second, // Default duration
			})
		}
	}

	fr.logger.Info("Discovered fuzz tests", zap.Int("count", len(tests)))
	return tests, nil
}

// RunAll runs all discovered fuzz tests
func (fr *FuzzRunner) RunAll(duration time.Duration) (*FuzzReport, error) {
	_, span := telemetry.Start(fr.rc.Ctx, "testing.RunAllFuzzTests")
	defer span.End()

	tests, err := fr.DiscoverFuzzTests()
	if err != nil {
		return nil, err
	}

	// Override duration if specified
	if duration > 0 {
		for i := range tests {
			tests[i].Duration = duration
		}
	}

	report := &FuzzReport{
		StartTime: time.Now(),
		Tests:     make([]FuzzResult, 0, len(tests)),
	}

	fr.logger.Info("Starting fuzz test execution",
		zap.Int("test_count", len(tests)),
		zap.Duration("duration", duration),
		zap.Int("parallel", fr.parallel))

	// Run tests with controlled parallelism
	sem := make(chan struct{}, fr.parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, test := range tests {
		wg.Add(1)
		go func(t FuzzTest) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			result := fr.runSingleTest(fr.rc.Ctx, t)

			mu.Lock()
			report.Tests = append(report.Tests, result)
			mu.Unlock()
		}(test)
	}

	wg.Wait()
	report.EndTime = time.Now()
	report.Duration = report.EndTime.Sub(report.StartTime)

	fr.logger.Info("Fuzz test execution completed",
		zap.Duration("total_duration", report.Duration),
		zap.Int("tests_run", len(report.Tests)))

	return report, nil
}

// runSingleTest executes a single fuzz test
func (fr *FuzzRunner) runSingleTest(ctx context.Context, test FuzzTest) FuzzResult {
	fr.logger.Info("Running fuzz test",
		zap.String("test", test.Name),
		zap.Duration("duration", test.Duration))

	result := FuzzResult{
		Test: test,
	}

	start := time.Now()

	// Build go test command
	args := []string{
		"test",
		fmt.Sprintf("-run=^%s$", test.Function),
		fmt.Sprintf("-fuzz=^%s$", test.Function),
		fmt.Sprintf("-fuzztime=%s", test.Duration),
		test.Package,
	}

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = fr.projectRoot

	output, err := cmd.CombinedOutput()
	result.Duration = time.Since(start)
	result.Output = string(output)

	if err != nil {
		result.Error = err
		result.Success = false

		// Parse output for crash information
		if strings.Contains(result.Output, "crash") {
			result.Crashes = fr.countCrashes(result.Output)
		}

		fr.logger.Error("Fuzz test failed",
			zap.String("test", test.Name),
			zap.Error(result.Error),
			zap.Int("crashes", result.Crashes))
	} else {
		result.Success = true

		// Parse coverage if available
		result.Coverage = fr.parseCoverage(result.Output)

		fr.logger.Info("Fuzz test passed",
			zap.String("test", test.Name),
			zap.Duration("duration", result.Duration))
	}

	return result
}

// countCrashes parses crash count from output
func (fr *FuzzRunner) countCrashes(output string) int {
	// Simple implementation - could be enhanced
	return strings.Count(output, "crash")
}

// parseCoverage extracts coverage percentage from output
func (fr *FuzzRunner) parseCoverage(output string) float64 {
	// Parse coverage from output
	// This is a simplified implementation
	return 0.0
}

// Summary generates a summary of the fuzz test results
func (r *FuzzReport) Summary() string {
	var buf strings.Builder

	totalTests := len(r.Tests)
	passed := 0
	failed := 0
	totalCrashes := 0

	for _, test := range r.Tests {
		if test.Success {
			passed++
		} else {
			failed++
			totalCrashes += test.Crashes
		}
	}

	buf.WriteString("=== Fuzz Test Summary ===\n")
	buf.WriteString(fmt.Sprintf("Total Tests: %d\n", totalTests))
	buf.WriteString(fmt.Sprintf("Passed: %d\n", passed))
	buf.WriteString(fmt.Sprintf("Failed: %d\n", failed))
	buf.WriteString(fmt.Sprintf("Total Crashes: %d\n", totalCrashes))
	buf.WriteString(fmt.Sprintf("Duration: %s\n", r.Duration))

	if failed > 0 {
		buf.WriteString("\nFailed Tests:\n")
		for _, test := range r.Tests {
			if !test.Success {
				buf.WriteString(fmt.Sprintf("  - %s (crashes: %d)\n",
					test.Test.Name, test.Crashes))
			}
		}
	}

	return buf.String()
}

// SaveReport saves the fuzz test report to a file
func (r *FuzzReport) SaveReport(path string) error {
	// Create detailed report content
	var buf strings.Builder

	buf.WriteString("# Eos Fuzz Test Report\n\n")
	buf.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("Start Time: %s\n", r.StartTime.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("End Time: %s\n", r.EndTime.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("Total Duration: %s\n\n", r.Duration))

	buf.WriteString("## Summary\n\n")
	buf.WriteString(r.Summary())
	buf.WriteString("\n")

	buf.WriteString("## Detailed Results\n\n")
	for _, test := range r.Tests {
		buf.WriteString(fmt.Sprintf("### %s\n\n", test.Test.Name))
		buf.WriteString(fmt.Sprintf("- **Package:** %s\n", test.Test.Package))
		buf.WriteString(fmt.Sprintf("- **Function:** %s\n", test.Test.Function))
		buf.WriteString(fmt.Sprintf("- **Duration:** %s\n", test.Duration))
		buf.WriteString(fmt.Sprintf("- **Success:** %t\n", test.Success))

		if test.Crashes > 0 {
			buf.WriteString(fmt.Sprintf("- **Crashes:** %d\n", test.Crashes))
		}

		if test.Error != nil {
			buf.WriteString(fmt.Sprintf("- **Error:** %s\n", test.Error))
		}

		if test.Output != "" {
			buf.WriteString("\n#### Output\n\n```\n")
			buf.WriteString(test.Output)
			buf.WriteString("\n```\n\n")
		}
	}

	return os.WriteFile(path, []byte(buf.String()), 0644)
}

// SetParallelism sets the number of parallel fuzz tests
func (fr *FuzzRunner) SetParallelism(parallel int) {
	if parallel > 0 {
		fr.parallel = parallel
	}
}
