package fuzzing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Runner implements the FuzzRunner interface
type Runner struct {
	config *Config
	logger otelzap.LoggerWithCtx
}

// NewRunner creates a new fuzzing runner
func NewRunner(rc *eos_io.RuntimeContext, config *Config) *Runner {
	return &Runner{
		config: config,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// DiscoverTests finds all available fuzz tests in the codebase
func (r *Runner) DiscoverTests(ctx context.Context) (*TestDiscovery, error) {
	r.logger.Info("Discovering fuzz tests")

	discovery := &TestDiscovery{
		SecurityCritical: []FuzzTest{},
		Architecture:     []FuzzTest{},
		Component:        []FuzzTest{},
	}

	// Walk through the codebase to find fuzz tests
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue despite errors
		}

		// Skip vendor and hidden directories
		if info.IsDir() && (info.Name() == "vendor" || strings.HasPrefix(info.Name(), ".")) {
			return filepath.SkipDir
		}

		// Look for fuzz test files
		if strings.HasSuffix(path, "_test.go") {
			tests, err := extractFuzzTests(path, r.logger)
			if err != nil {
				r.logger.Debug("Failed to extract fuzz tests",
					zap.String("file", path),
					zap.Error(err))
				return nil // Continue despite errors
			}

			// Categorize tests
			for _, test := range tests {
				test = categorizeTest(test, path)

				switch test.Category {
				case CategorySecurityCritical:
					discovery.SecurityCritical = append(discovery.SecurityCritical, test)
				case CategoryArchitecture:
					discovery.Architecture = append(discovery.Architecture, test)
				default:
					discovery.Component = append(discovery.Component, test)
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to discover tests: %w", err)
	}

	totalTests := len(discovery.SecurityCritical) + len(discovery.Architecture) + len(discovery.Component)
	r.logger.Info("Test discovery completed",
		zap.Int("security_critical", len(discovery.SecurityCritical)),
		zap.Int("architecture", len(discovery.Architecture)),
		zap.Int("component", len(discovery.Component)),
		zap.Int("total", totalTests))

	return discovery, nil
}

// RunTest executes a single fuzz test
func (r *Runner) RunTest(ctx context.Context, test FuzzTest, config Config) (*TestResult, error) {
	r.logger.Debug("Running fuzz test",
		zap.String("test", test.Name),
		zap.String("package", test.Package),
		zap.Duration("duration", config.Duration))

	startTime := time.Now()

	// Build the go test command
	// #nosec G204 -- Test function and package are discovered from local codebase, duration is validated
	cmd := exec.CommandContext(ctx, "go", "test",
		"-fuzz="+test.Function,
		"-fuzztime="+config.Duration.String(),
		test.Package)

	// Set environment variables
	env := os.Environ()
	if config.Verbose {
		env = append(env, "VERBOSE=true")
	}
	cmd.Env = env

	// Capture output
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	result := &TestResult{
		TestName: test.Name,
		Package:  test.Package,
		Duration: duration,
		Success:  err == nil,
	}

	// Parse fuzzing output for statistics
	if err == nil {
		parseOutput := string(output)
		result.Executions = extractExecutionCount(parseOutput)
		result.ExecRate = float64(result.Executions) / duration.Seconds()
		result.NewInputs = extractNewInputs(parseOutput)
	} else {
		result.ErrorMessage = err.Error()
		result.CrashData = extractCrashData(string(output))
	}

	r.logger.Debug("Fuzz test completed",
		zap.String("test", test.Name),
		zap.Bool("success", result.Success),
		zap.Duration("duration", result.Duration),
		zap.Int64("executions", result.Executions))

	return result, nil
}

// RunSession executes a complete fuzzing session
func (r *Runner) RunSession(ctx context.Context, config Config) (*FuzzSession, error) {
	r.logger.Info("Starting fuzzing session",
		zap.Duration("duration", config.Duration),
		zap.Int("parallel_jobs", config.ParallelJobs),
		zap.Bool("security_focus", config.SecurityFocus))

	sessionID := fmt.Sprintf("session_%d", time.Now().Unix())
	session := &FuzzSession{
		ID:        sessionID,
		StartTime: time.Now(),
		Config:    config,
		Results:   []TestResult{},
		LogDir:    config.LogDir,
	}

	// Discover tests
	discovery, err := r.DiscoverTests(ctx)
	if err != nil {
		return nil, fmt.Errorf("test discovery failed: %w", err)
	}

	// Select tests based on configuration
	testsToRun := r.selectTests(discovery, config)

	if len(testsToRun) == 0 {
		r.logger.Warn("No tests selected for execution")
		session.EndTime = time.Now()
		session.Summary = r.calculateSummary(session.Results)
		return session, nil
	}

	r.logger.Info("Selected tests for execution",
		zap.Int("total_tests", len(testsToRun)))

	// Execute tests
	results := make(chan TestResult, len(testsToRun))
	errors := make(chan error, len(testsToRun))

	// Run tests with controlled parallelism
	semaphore := make(chan struct{}, config.ParallelJobs)

	for _, test := range testsToRun {
		go func(t FuzzTest) {
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			result, err := r.RunTest(ctx, t, config)
			if err != nil {
				errors <- fmt.Errorf("test %s failed: %w", t.Name, err)
				return
			}
			results <- *result
		}(test)
	}

	// Collect results
	for i := 0; i < len(testsToRun); i++ {
		select {
		case result := <-results:
			session.Results = append(session.Results, result)
		case err := <-errors:
			r.logger.Error("Test execution error", zap.Error(err))
			// Continue with other tests
		case <-ctx.Done():
			return nil, fmt.Errorf("session cancelled: %w", ctx.Err())
		}
	}

	session.EndTime = time.Now()
	session.Summary = r.calculateSummary(session.Results)

	r.logger.Info("Fuzzing session completed",
		zap.String("session_id", sessionID),
		zap.Int("total_tests", session.Summary.TotalTests),
		zap.Int("passed_tests", session.Summary.PassedTests),
		zap.Int("failed_tests", session.Summary.FailedTests),
		zap.Duration("total_duration", session.Summary.TotalDuration))

	return session, nil
}

// GenerateReport creates a formatted report for the fuzzing session
func (r *Runner) GenerateReport(session *FuzzSession) (string, error) {
	switch session.Config.ReportFormat {
	case ReportFormatMarkdown:
		return r.generateMarkdownReport(session)
	case ReportFormatJSON:
		return r.generateJSONReport(session)
	case ReportFormatText:
		return r.generateTextReport(session)
	default:
		return r.generateMarkdownReport(session)
	}
}

// Helper functions

func extractFuzzTests(filePath string, _ otelzap.LoggerWithCtx) ([]FuzzTest, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Look for Fuzz functions
	fuzzRegex := regexp.MustCompile(`func\s+(Fuzz\w+)\s*\(`)
	matches := fuzzRegex.FindAllStringSubmatch(string(content), -1)

	var tests []FuzzTest
	packageName := extractPackageName(filePath)

	for _, match := range matches {
		if len(match) >= 2 {
			test := FuzzTest{
				Name:     match[1],
				Package:  packageName,
				Function: match[1],
				Priority: 1, // Default priority
			}
			tests = append(tests, test)
		}
	}

	return tests, nil
}

func categorizeTest(test FuzzTest, filePath string) FuzzTest {
	// Categorize based on package path and test name
	path := strings.ToLower(filePath)
	name := strings.ToLower(test.Name)

	// Security-critical tests
	if strings.Contains(path, "crypto") ||
		strings.Contains(path, "security") ||
		strings.Contains(path, "auth") ||
		strings.Contains(path, "vault") ||
		strings.Contains(path, "network") ||
		strings.Contains(path, "config") ||
		strings.Contains(name, "security") ||
		strings.Contains(name, "crypto") ||
		strings.Contains(name, "password") ||
		strings.Contains(name, "token") ||
		strings.Contains(name, "sql") ||
		strings.Contains(name, "injection") ||
		strings.Contains(name, "xss") ||
		strings.Contains(name, "path") ||
		strings.Contains(name, "traversal") ||
		strings.Contains(name, "validation") ||
		strings.Contains(name, "http") ||
		strings.Contains(name, "dns") ||
		strings.Contains(name, "url") ||
		strings.Contains(name, "json") ||
		strings.Contains(name, "yaml") ||
		strings.Contains(name, "toml") ||
		strings.Contains(name, "regex") {
		test.Category = CategorySecurityCritical
		test.Priority = 1
		test.Description = "Security-critical functionality test"
		return test
	}

	// Architecture tests
	if strings.Contains(path, "") ||
		strings.Contains(path, "terraform") ||
		strings.Contains(path, "nomad") ||
		strings.Contains(name, "orchestrat") ||
		strings.Contains(name, "deploy") {
		test.Category = CategoryArchitecture
		test.Priority = 2
		test.Description = "Architecture and orchestration test"
		return test
	}

	// Component tests (default)
	test.Category = CategoryComponent
	test.Priority = 3
	test.Description = "Component functionality test"
	return test
}

func extractPackageName(filePath string) string {
	// Convert file path to package path
	dir := filepath.Dir(filePath)
	if dir == "." {
		return "."
	}

	// Convert to Go package format
	return "./" + filepath.ToSlash(dir)
}

func extractExecutionCount(output string) int64 {
	// Look for execution count in fuzzing output
	// Format: "fuzz: elapsed: 3s, execs: 18206 (6068/sec)"
	execRegex := regexp.MustCompile(`execs:\s*(\d+)`)
	matches := execRegex.FindStringSubmatch(output)

	if len(matches) >= 2 {
		if count, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			return count
		}
	}

	return 0
}

func extractNewInputs(output string) int {
	// Look for new interesting inputs
	// Format: "new interesting: 12 (total: 204)"
	inputRegex := regexp.MustCompile(`new interesting:\s*(\d+)`)
	matches := inputRegex.FindStringSubmatch(output)

	if len(matches) >= 2 {
		if count, err := strconv.Atoi(matches[1]); err == nil {
			return count
		}
	}

	return 0
}

func extractCrashData(output string) *CrashData {
	// Look for panic or crash information
	if strings.Contains(output, "panic:") || strings.Contains(output, "FAIL:") {
		crash := &CrashData{
			Severity: "medium",
		}

		// Extract panic reason
		panicRegex := regexp.MustCompile(`panic:\s*(.+)`)
		if matches := panicRegex.FindStringSubmatch(output); len(matches) >= 2 {
			crash.PanicReason = matches[1]
		}

		// Extract failing input if available
		inputRegex := regexp.MustCompile(`\s+input:\s*(.+)`)
		if matches := inputRegex.FindStringSubmatch(output); len(matches) >= 2 {
			crash.Input = matches[1]
		}

		// Include relevant stack trace lines
		lines := strings.Split(output, "\n")
		var stackLines []string
		for _, line := range lines {
			if strings.Contains(line, ".go:") || strings.Contains(line, "panic") {
				stackLines = append(stackLines, line)
				if len(stackLines) >= 10 { // Limit stack trace length
					break
				}
			}
		}
		crash.StackTrace = strings.Join(stackLines, "\n")

		return crash
	}

	return nil
}

func (r *Runner) selectTests(discovery *TestDiscovery, config Config) []FuzzTest {
	var tests []FuzzTest

	// Always include security-critical tests if security focus is enabled
	if config.SecurityFocus {
		tests = append(tests, discovery.SecurityCritical...)
	}

	// Include architecture tests if enabled
	if config.ArchitectureTesting {
		tests = append(tests, discovery.Architecture...)
	}

	// Include component tests
	tests = append(tests, discovery.Component...)

	// Limit tests in CI mode
	if config.CIMode && len(tests) > 20 {
		// Prioritize security tests in CI
		var prioritized []FuzzTest
		prioritized = append(prioritized, discovery.SecurityCritical...)

		// Add some component tests
		remaining := 20 - len(prioritized)
		if remaining > 0 && len(discovery.Component) > 0 {
			limit := min(remaining, len(discovery.Component))
			prioritized = append(prioritized, discovery.Component[:limit]...)
		}

		tests = prioritized
	}

	return tests
}

func (r *Runner) calculateSummary(results []TestResult) SessionSummary {
	summary := SessionSummary{
		TotalTests: len(results),
	}

	for _, result := range results {
		summary.TotalExecutions += result.Executions
		summary.TotalDuration += result.Duration

		if result.Success {
			summary.PassedTests++
		} else {
			summary.FailedTests++
			if result.CrashData != nil {
				summary.CrashesFound++
				summary.SecurityAlert = true
			}
		}
	}

	if summary.TotalTests > 0 {
		summary.SuccessRate = float64(summary.PassedTests) / float64(summary.TotalTests)
	}

	return summary
}

func (r *Runner) generateMarkdownReport(session *FuzzSession) (string, error) {
	var report strings.Builder

	report.WriteString("# Fuzzing Session Report\n\n")
	report.WriteString(fmt.Sprintf("**Session ID:** %s\n", session.ID))
	report.WriteString(fmt.Sprintf("**Start Time:** %s\n", session.StartTime.Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("**End Time:** %s\n", session.EndTime.Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("**Duration:** %s\n\n", session.Summary.TotalDuration))

	// Summary
	report.WriteString("## Summary\n\n")
	report.WriteString(fmt.Sprintf("- **Total Tests:** %d\n", session.Summary.TotalTests))
	report.WriteString(fmt.Sprintf("- **Passed:** %d\n", session.Summary.PassedTests))
	report.WriteString(fmt.Sprintf("- **Failed:** %d\n", session.Summary.FailedTests))
	report.WriteString(fmt.Sprintf("- **Success Rate:** %.1f%%\n", session.Summary.SuccessRate*100))
	report.WriteString(fmt.Sprintf("- **Total Executions:** %d\n", session.Summary.TotalExecutions))

	if session.Summary.SecurityAlert {
		report.WriteString("\n **SECURITY ALERT:** Crashes detected during fuzzing!\n")
	}

	// Test Results
	report.WriteString("\n## Test Results\n\n")
	for _, result := range session.Results {
		status := " PASS"
		if !result.Success {
			status = " FAIL"
		}

		report.WriteString(fmt.Sprintf("### %s %s\n", status, result.TestName))
		report.WriteString(fmt.Sprintf("- **Package:** %s\n", result.Package))
		report.WriteString(fmt.Sprintf("- **Duration:** %s\n", result.Duration))
		report.WriteString(fmt.Sprintf("- **Executions:** %d\n", result.Executions))

		if result.CrashData != nil {
			report.WriteString(fmt.Sprintf("- ** Crash Detected:** %s\n", result.CrashData.PanicReason))
		}

		report.WriteString("\n")
	}

	return report.String(), nil
}

func (r *Runner) generateJSONReport(_ *FuzzSession) (string, error) {
	// Would implement JSON serialization of session
	return "{\"error\": \"JSON report not implemented yet\"}", nil
}

func (r *Runner) generateTextReport(session *FuzzSession) (string, error) {
	var report strings.Builder

	report.WriteString("FUZZING SESSION REPORT\n")
	report.WriteString("=====================\n\n")
	report.WriteString(fmt.Sprintf("Session ID: %s\n", session.ID))
	report.WriteString(fmt.Sprintf("Duration: %s\n", session.Summary.TotalDuration))
	report.WriteString(fmt.Sprintf("Tests: %d/%d passed (%.1f%%)\n",
		session.Summary.PassedTests,
		session.Summary.TotalTests,
		session.Summary.SuccessRate*100))

	if session.Summary.SecurityAlert {
		report.WriteString("\n*** SECURITY ALERT: Crashes detected! ***\n")
	}

	return report.String(), nil
}
