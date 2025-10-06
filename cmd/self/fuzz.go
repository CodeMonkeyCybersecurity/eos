package self

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/fuzzing"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Fuzzing testing commands for Eos",
	Long: `Fuzzing testing commands provide comprehensive security and robustness testing
for the Eos codebase using Go's native fuzzing capabilities.

Available subcommands:
  quick      - Quick validation fuzzing (30s)
  security   - Security-focused fuzzing (5m)
  overnight  - Extended overnight fuzzing (8h+)
  ci         - CI/CD optimized fuzzing
  verify     - Verify fuzzing environment

Examples:
  eos self fuzz quick
  eos self fuzz security --duration 10m
  eos self fuzz overnight --long-duration 12h
  eos self fuzz ci --mode pr-validation`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("No subcommand provided for fuzz command", zap.String("command", cmd.Use))
		return cmd.Help()
	}),
}

var fuzzQuickCmd = &cobra.Command{
	Use:   "quick",
	Short: "Run quick fuzzing validation (30s default)",
	Long: `Run quick fuzzing validation to catch obvious issues quickly.
This is ideal for pre-commit checks and rapid development cycles.

Default configuration:
- Duration: 30 seconds
- Security focus: enabled
- Parallel jobs: 4
- Fail fast: enabled`,

	RunE: eos_cli.Wrap(runFuzzQuick),
}

var fuzzSecurityCmd = &cobra.Command{
	Use:   "security",
	Short: "Run security-focused fuzzing (5m default)",
	Long: `Run comprehensive security-focused fuzzing to identify potential
vulnerabilities and security issues in critical components.

Default configuration:
- Duration: 5 minutes
- Security focus: enabled
- Architecture testing: disabled
- Verbose logging: enabled
- Parallel jobs: 4`,

	RunE: eos_cli.Wrap(runFuzzSecurity),
}

var fuzzOvernightCmd = &cobra.Command{
	Use:   "overnight",
	Short: "Run extended overnight fuzzing",
	Long: `Run comprehensive overnight fuzzing with extended durations
for thorough testing of the entire codebase.

Default configuration:
- Short tests: 30 minutes
- Medium tests: 2 hours  
- Long tests: 8 hours
- Security focus: enabled
- Architecture testing: enabled
- Verbose logging: enabled`,

	RunE: eos_cli.Wrap(runFuzzOvernight),
}

var fuzzCICmd = &cobra.Command{
	Use:   "ci",
	Short: "Run CI/CD optimized fuzzing",
	Long: `Run fuzzing optimized for CI/CD environments with configurable
profiles for different pipeline stages.

Available profiles:
- pr-validation: Quick validation for pull requests
- security-focused: Security testing for merge requests
- architecture: Architecture compliance testing
- full: Complete testing suite`,

	RunE: eos_cli.Wrap(runFuzzCI),
}

var fuzzVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify fuzzing environment setup",
	Long: `Verify that the fuzzing environment is properly configured
and all prerequisites are satisfied for running fuzz tests.

This command checks:
- Go installation and version
- Fuzzing support availability
- Test discovery and compilation
- Environment configuration`,

	RunE: eos_cli.Wrap(runFuzzVerify),
}

func init() {
	// Add fuzz command to self
	SelfCmd.AddCommand(fuzzCmd)

	// Add subcommands to fuzz
	fuzzCmd.AddCommand(fuzzQuickCmd)
	fuzzCmd.AddCommand(fuzzSecurityCmd)
	fuzzCmd.AddCommand(fuzzOvernightCmd)
	fuzzCmd.AddCommand(fuzzCICmd)
	fuzzCmd.AddCommand(fuzzVerifyCmd)

	// Quick command flags
	fuzzQuickCmd.Flags().DurationP("duration", "d", 30*time.Second, "Duration for quick fuzzing")
	fuzzQuickCmd.Flags().IntP("parallel-jobs", "j", 4, "Number of parallel jobs")
	fuzzQuickCmd.Flags().String("log-dir", "", "Log directory (default: ~/.cache/eos-fuzz)")
	fuzzQuickCmd.Flags().Bool("verbose", false, "Enable verbose logging")

	// Security command flags
	fuzzSecurityCmd.Flags().DurationP("duration", "d", 5*time.Minute, "Duration for security fuzzing")
	fuzzSecurityCmd.Flags().IntP("parallel-jobs", "j", 4, "Number of parallel jobs")
	fuzzSecurityCmd.Flags().String("log-dir", "", "Log directory (default: ~/.cache/eos-fuzz)")
	fuzzSecurityCmd.Flags().Bool("verbose", true, "Enable verbose logging")
	fuzzSecurityCmd.Flags().Bool("fail-fast", false, "Stop on first failure")

	// Overnight command flags
	fuzzOvernightCmd.Flags().Duration("short-duration", 30*time.Minute, "Duration for short tests")
	fuzzOvernightCmd.Flags().Duration("medium-duration", 2*time.Hour, "Duration for medium tests")
	fuzzOvernightCmd.Flags().Duration("long-duration", 8*time.Hour, "Duration for long tests")
	fuzzOvernightCmd.Flags().IntP("parallel-jobs", "j", 4, "Number of parallel jobs")
	fuzzOvernightCmd.Flags().String("log-dir", "", "Log directory (default: ~/.cache/eos-fuzz)")
	fuzzOvernightCmd.Flags().Bool("verbose", true, "Enable verbose logging")

	// CI command flags
	fuzzCICmd.Flags().String("mode", "pr-validation", "CI mode (pr-validation, security-focused, architecture, full)")
	fuzzCICmd.Flags().DurationP("duration", "d", 60*time.Second, "Duration for CI fuzzing")
	fuzzCICmd.Flags().IntP("parallel-jobs", "j", 4, "Number of parallel jobs")
	fuzzCICmd.Flags().String("log-dir", "", "Log directory (default: ./fuzz-results)")
	fuzzCICmd.Flags().Bool("fail-fast", true, "Stop on first failure")
	fuzzCICmd.Flags().String("report-format", "markdown", "Report format (markdown, json, text)")

	// Verify command flags
	fuzzVerifyCmd.Flags().Bool("verbose", false, "Enable verbose verification output")
}

func runFuzzQuick(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting quick fuzzing validation")

	// Parse flags
	duration, _ := cmd.Flags().GetDuration("duration")
	parallelJobs, _ := cmd.Flags().GetInt("parallel-jobs")
	logDir, _ := cmd.Flags().GetString("log-dir")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Create configuration
	config := &fuzzing.Config{
		Duration:            duration,
		ParallelJobs:        parallelJobs,
		LogDir:              logDir,
		Verbose:             verbose,
		SecurityFocus:       true,
		ArchitectureTesting: false,
		FailFast:            true,
		ReportFormat:        fuzzing.ReportFormatMarkdown,
	}

	return executeFuzzing(rc, config, "quick")
}

func runFuzzSecurity(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting security-focused fuzzing")

	// Parse flags
	duration, _ := cmd.Flags().GetDuration("duration")
	parallelJobs, _ := cmd.Flags().GetInt("parallel-jobs")
	logDir, _ := cmd.Flags().GetString("log-dir")
	verbose, _ := cmd.Flags().GetBool("verbose")
	failFast, _ := cmd.Flags().GetBool("fail-fast")

	// Create configuration
	config := &fuzzing.Config{
		Duration:            duration,
		ParallelJobs:        parallelJobs,
		LogDir:              logDir,
		Verbose:             verbose,
		SecurityFocus:       true,
		ArchitectureTesting: false,
		FailFast:            failFast,
		ReportFormat:        fuzzing.ReportFormatMarkdown,
	}

	return executeFuzzing(rc, config, "security")
}

func runFuzzOvernight(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting overnight fuzzing session")

	// Parse flags
	shortDuration, _ := cmd.Flags().GetDuration("short-duration")
	mediumDuration, _ := cmd.Flags().GetDuration("medium-duration")
	longDuration, _ := cmd.Flags().GetDuration("long-duration")
	parallelJobs, _ := cmd.Flags().GetInt("parallel-jobs")
	logDir, _ := cmd.Flags().GetString("log-dir")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Create configuration for overnight testing
	config := &fuzzing.Config{
		Duration:            longDuration, // Start with long duration
		ShortDuration:       shortDuration,
		MediumDuration:      mediumDuration,
		LongDuration:        longDuration,
		ParallelJobs:        parallelJobs,
		LogDir:              logDir,
		Verbose:             verbose,
		SecurityFocus:       true,
		ArchitectureTesting: true,
		FailFast:            false,
		ReportFormat:        fuzzing.ReportFormatMarkdown,
	}

	return executeFuzzing(rc, config, "overnight")
}

func runFuzzCI(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting CI fuzzing session")

	// Parse flags
	mode, _ := cmd.Flags().GetString("mode")
	duration, _ := cmd.Flags().GetDuration("duration")
	parallelJobs, _ := cmd.Flags().GetInt("parallel-jobs")
	logDir, _ := cmd.Flags().GetString("log-dir")
	failFast, _ := cmd.Flags().GetBool("fail-fast")
	reportFormat, _ := cmd.Flags().GetString("report-format")

	// Set CI-specific defaults
	if logDir == "" {
		logDir = "./fuzz-results"
	}

	// Create configuration
	config := &fuzzing.Config{
		Duration:     duration,
		ParallelJobs: parallelJobs,
		LogDir:       logDir,
		Verbose:      false, // Less verbose in CI
		CIMode:       true,
		CIProfile:    mode,
		FailFast:     failFast,
		ReportFormat: reportFormat,
	}

	// Configure based on CI mode
	switch mode {
	case fuzzing.CIProfilePRValidation:
		config.SecurityFocus = true
		config.ArchitectureTesting = false
	case fuzzing.CIProfileSecurityFocus:
		config.SecurityFocus = true
		config.ArchitectureTesting = false
		config.Duration = 2 * time.Minute
	case fuzzing.CIProfileArchitecture:
		config.SecurityFocus = false
		config.ArchitectureTesting = true
		config.Duration = 3 * time.Minute
	case fuzzing.CIProfileFull:
		config.SecurityFocus = true
		config.ArchitectureTesting = true
		config.Duration = 5 * time.Minute
	default:
		return fmt.Errorf("invalid CI mode: %s, valid options: %s, %s, %s, %s",
			mode, fuzzing.CIProfilePRValidation, fuzzing.CIProfileSecurityFocus,
			fuzzing.CIProfileArchitecture, fuzzing.CIProfileFull)
	}

	return executeFuzzing(rc, config, "ci")
}

func runFuzzVerify(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying fuzzing environment")

	verbose, _ := cmd.Flags().GetBool("verbose")

	// ASSESS - Check if verification is needed
	logger.Info("Assessing fuzzing environment verification requirements")

	// INTERVENE - Run verification
	if err := fuzzing.Verify(rc); err != nil {
		logger.Error("Fuzzing environment verification failed", zap.Error(err))
		return fmt.Errorf("fuzzing environment verification failed: %w", err)
	}

	// EVALUATE - Report results
	logger.Info("Fuzzing environment verification completed successfully")

	if verbose {
		logger.Info("Fuzzing environment is ready for use",
			zap.String("go_version", "detected"),
			zap.String("fuzzing_support", "available"),
			zap.String("status", "verified"))
	}

	return nil
}

// executeFuzzing is the common fuzzing execution logic
func executeFuzzing(rc *eos_io.RuntimeContext, config *fuzzing.Config, mode string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites and setup
	logger.Info("Assessing fuzzing prerequisites", zap.String("mode", mode))

	if err := fuzzing.Install(rc, config); err != nil {
		return fmt.Errorf("fuzzing installation failed: %w", err)
	}

	if err := fuzzing.Configure(rc, config); err != nil {
		return fmt.Errorf("fuzzing configuration failed: %w", err)
	}

	// INTERVENE - Execute fuzzing
	logger.Info("Executing fuzzing session",
		zap.String("mode", mode),
		zap.Duration("duration", config.Duration),
		zap.Int("parallel_jobs", config.ParallelJobs))

	runner := fuzzing.NewRunner(rc, config)
	session, err := runner.RunSession(rc.Ctx, *config)
	if err != nil {
		return fmt.Errorf("fuzzing session failed: %w", err)
	}

	// EVALUATE - Generate and save report
	logger.Info("Generating fuzzing report")

	report, err := runner.GenerateReport(session)
	if err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	// Save report to file
	reportPath := filepath.Join(config.LogDir, fmt.Sprintf("fuzz-report-%s-%d.md", mode, time.Now().Unix()))
	if err := os.WriteFile(reportPath, []byte(report), 0644); err != nil {
		logger.Warn("Failed to save report to file", zap.Error(err))
	} else {
		logger.Info("Report saved", zap.String("path", reportPath))
	}

	// Log summary
	logger.Info("Fuzzing session completed",
		zap.String("mode", mode),
		zap.String("session_id", session.ID),
		zap.Int("total_tests", session.Summary.TotalTests),
		zap.Int("passed_tests", session.Summary.PassedTests),
		zap.Int("failed_tests", session.Summary.FailedTests),
		zap.Float64("success_rate", session.Summary.SuccessRate),
		zap.Duration("total_duration", session.Summary.TotalDuration))

	// Check for security alerts
	if session.Summary.SecurityAlert {
		logger.Error("🚨 SECURITY ALERT: Crashes detected during fuzzing!",
			zap.Int("crashes_found", session.Summary.CrashesFound))

		if config.FailFast {
			return fmt.Errorf("fuzzing detected security issues (crashes: %d)", session.Summary.CrashesFound)
		}
	}

	// Print summary to user
	if config.Verbose {
		logger.Info("terminal prompt: === Fuzzing Session Summary ===")
		logger.Info("terminal prompt: Mode", zap.String("mode", mode))
		fmt.Printf("Tests: %d/%d passed (%.1f%%)\n",
			session.Summary.PassedTests,
			session.Summary.TotalTests,
			session.Summary.SuccessRate*100)
		logger.Info("terminal prompt: Duration", zap.Duration("duration", session.Summary.TotalDuration))
		logger.Info("terminal prompt: Report", zap.String("path", reportPath))

		if session.Summary.SecurityAlert {
			logger.Info("terminal prompt: Security Alert - crashes detected", zap.Int("crashes", session.Summary.CrashesFound))
		}
	}

	return nil
}
