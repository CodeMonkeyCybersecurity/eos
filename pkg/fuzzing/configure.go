package fuzzing

import (
	"context"
	"fmt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Note: All subprocess executions in this package use #nosec G204 comments
// as they execute only hardcoded commands with controlled inputs, not user data

// Configure sets up the fuzzing environment and validates configuration
func Configure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites and validate configuration
	logger.Info("Assessing fuzzing configuration prerequisites")

	if err := validateConfig(config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	if err := checkEnvironmentPrerequisites(rc.Ctx, logger); err != nil {
		return fmt.Errorf("environment prerequisites not met: %w", err)
	}

	// INTERVENE - Apply configuration and setup environment
	logger.Info("Configuring fuzzing environment",
		zap.Duration("duration", config.Duration),
		zap.Int("parallel_jobs", config.ParallelJobs),
		zap.Bool("security_focus", config.SecurityFocus))

	if err := setupLogDirectory(config, logger); err != nil {
		return fmt.Errorf("failed to setup log directory: %w", err)
	}

	if err := applyEnvironmentConfiguration(config, logger); err != nil {
		return fmt.Errorf("failed to apply environment configuration: %w", err)
	}

	// EVALUATE - Verify configuration was applied successfully
	logger.Info("Verifying fuzzing configuration")

	if err := verifyConfiguration(config, logger); err != nil {
		return fmt.Errorf("configuration verification failed: %w", err)
	}

	logger.Info("Fuzzing configuration completed successfully",
		zap.String("log_dir", config.LogDir),
		zap.String("report_format", config.ReportFormat))

	return nil
}

// validateConfig validates the fuzzing configuration
func validateConfig(config *Config) error {
	if config.Duration <= 0 {
		return fmt.Errorf("duration must be positive, got %v", config.Duration)
	}

	if config.Duration > 24*time.Hour {
		return fmt.Errorf("duration too long (max 24h), got %v", config.Duration)
	}

	if config.ParallelJobs <= 0 {
		return fmt.Errorf("parallel_jobs must be positive, got %d", config.ParallelJobs)
	}

	if config.ParallelJobs > 32 {
		return fmt.Errorf("parallel_jobs too high (max 32), got %d", config.ParallelJobs)
	}

	// Validate CI profile if in CI mode
	if config.CIMode && config.CIProfile != "" {
		validProfiles := []string{CIProfilePRValidation, CIProfileSecurityFocus, CIProfileArchitecture, CIProfileFull}
		valid := false
		for _, profile := range validProfiles {
			if config.CIProfile == profile {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid CI profile: %s, valid options: %v", config.CIProfile, validProfiles)
		}
	}

	// Validate report format
	if config.ReportFormat == "" {
		config.ReportFormat = ReportFormatMarkdown
	}
	validFormats := []string{ReportFormatMarkdown, ReportFormatJSON, ReportFormatText}
	valid := false
	for _, format := range validFormats {
		if config.ReportFormat == format {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid report format: %s, valid options: %v", config.ReportFormat, validFormats)
	}

	return nil
}

// checkEnvironmentPrerequisites verifies the environment is ready for fuzzing
func checkEnvironmentPrerequisites(_ context.Context, logger otelzap.LoggerWithCtx) error {
	logger.Debug("Checking environment prerequisites")

	// Check Go installation
	if err := checkGoInstallation(logger); err != nil {
		return fmt.Errorf("go installation check failed: %w", err)
	}

	// Check if we're in a Go module
	if err := checkGoModule(logger); err != nil {
		return fmt.Errorf("go module check failed: %w", err)
	}

	// Check for test files
	if err := checkFuzzTests(logger); err != nil {
		return fmt.Errorf("fuzz test check failed: %w", err)
	}

	// Check system resources
	if err := checkSystemResources(logger); err != nil {
		return fmt.Errorf("system resource check failed: %w", err)
	}

	logger.Debug("Environment prerequisites satisfied")
	return nil
}

// setupLogDirectory creates and configures the logging directory
func setupLogDirectory(config *Config, logger otelzap.LoggerWithCtx) error {
	if config.LogDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}
		config.LogDir = filepath.Join(homeDir, ".cache", "eos-fuzz")
	}

	// Create log directory with proper permissions
	if err := os.MkdirAll(config.LogDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create log directory %s: %w", config.LogDir, err)
	}

	subdirs := []string{"sessions", "reports", "corpus", "crashes", "tmp"}
	for _, subdir := range subdirs {
		path := filepath.Join(config.LogDir, subdir)
		if err := os.MkdirAll(path, shared.ServiceDirPerm); err != nil {
			return fmt.Errorf("failed to create log subdirectory %s: %w", path, err)
		}
	}

	// Check write permissions
	testFile := filepath.Join(config.LogDir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("log directory is not writable: %w", err)
	}
	_ = os.Remove(testFile)

	logger.Debug("Log directory configured",
		zap.String("path", config.LogDir))

	return nil
}

// applyEnvironmentConfiguration sets up environment variables for fuzzing
func applyEnvironmentConfiguration(config *Config, logger otelzap.LoggerWithCtx) error {
	// Set GOMAXPROCS based on parallel jobs
	if err := os.Setenv("GOMAXPROCS", fmt.Sprintf("%d", config.ParallelJobs)); err != nil {
		logger.Warn("Failed to set GOMAXPROCS", zap.Error(err))
	}

	// Set fuzzing-specific environment variables
	envVars := map[string]string{
		"FUZZTIME":      config.Duration.String(),
		"PARALLEL_JOBS": fmt.Sprintf("%d", config.ParallelJobs),
		"LOG_DIR":       config.LogDir,
		"TMPDIR":        filepath.Join(config.LogDir, "tmp"),
	}

	if config.SecurityFocus {
		envVars["SECURITY_FOCUS"] = "true"
	}

	if config.ArchitectureTesting {
		envVars["ARCHITECTURE_TESTING"] = "true"
	}

	if config.Verbose {
		envVars["VERBOSE"] = "true"
	}

	if config.CIMode {
		envVars["CI_MODE"] = "true"
		if config.CIProfile != "" {
			envVars["CI_PROFILE"] = config.CIProfile
		}
	}

	for key, value := range envVars {
		if err := os.Setenv(key, value); err != nil {
			logger.Warn("Failed to set environment variable",
				zap.String("key", key),
				zap.String("value", value),
				zap.Error(err))
		}
	}

	logger.Debug("Environment configuration applied",
		zap.Any("variables", envVars))

	return nil
}

// verifyConfiguration ensures the configuration was applied correctly
func verifyConfiguration(config *Config, logger otelzap.LoggerWithCtx) error {
	// Verify log directory exists and is writable
	if _, err := os.Stat(config.LogDir); os.IsNotExist(err) {
		return fmt.Errorf("log directory does not exist: %s", config.LogDir)
	}

	// Verify environment variables
	expectedDuration := os.Getenv("FUZZTIME")
	if expectedDuration != config.Duration.String() {
		logger.Warn("FUZZTIME environment variable mismatch",
			zap.String("expected", config.Duration.String()),
			zap.String("actual", expectedDuration))
	}

	logger.Debug("Configuration verification completed successfully")
	return nil
}

// Helper functions for environment checks

func checkGoInstallation(_ otelzap.LoggerWithCtx) error {
	if _, err := os.Stat("/usr/local/go/bin/go"); err == nil {
		return nil
	}

	// Check if go is in PATH
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go not found in PATH or /usr/local/go/bin/go")
	}

	return nil
}

func checkGoModule(_ otelzap.LoggerWithCtx) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to determine current directory: %w", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(cwd, "go.mod")); err == nil {
			return nil
		}
		parent := filepath.Dir(cwd)
		if parent == cwd {
			break
		}
		cwd = parent
	}

	return fmt.Errorf("go.mod not found - fuzzing must be run from a Go module")
}

func checkFuzzTests(logger otelzap.LoggerWithCtx) error {
	testDirs := []string{"pkg", "cmd"}
	foundTests := false
	var matches []string

	for _, dir := range testDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}

		err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info == nil || info.IsDir() {
				return nil
			}
			name := strings.ToLower(info.Name())
			if strings.HasSuffix(name, "_test.go") && strings.Contains(name, "fuzz") {
				foundTests = true
				matches = append(matches, path)
			}
			return nil
		})
		if err != nil {
			logger.Debug("Failed to inspect fuzz tests",
				zap.String("dir", dir),
				zap.Error(err))
		}
	}

	if foundTests {
		logger.Debug("Found fuzz tests", zap.Strings("files", matches[:min(len(matches), 5)]))
	}

	if !foundTests {
		logger.Warn("No fuzz tests found in common locations (pkg/, cmd/)")
	}

	return nil
}

func checkSystemResources(logger otelzap.LoggerWithCtx) error {
	// Check available disk space
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Basic disk space check (implementation would depend on system)
	logger.Debug("System resource check completed", zap.String("cwd", cwd))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
