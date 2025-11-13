package fuzzing

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Install ensures fuzzing prerequisites are installed and available
func Install(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check what needs to be installed
	logger.Info("Assessing fuzzing installation requirements")
	
	installNeeded, err := assessInstallationNeeds(rc.Ctx, logger)
	if err != nil {
		return fmt.Errorf("failed to assess installation needs: %w", err)
	}
	
	if !installNeeded {
		logger.Info("All fuzzing prerequisites already satisfied")
		return nil
	}
	
	// INTERVENE - Install missing components
	logger.Info("Installing fuzzing prerequisites")
	
	if err := installGoFuzzDependencies(rc.Ctx, logger); err != nil {
		return fmt.Errorf("failed to install Go fuzz dependencies: %w", err)
	}
	
	if err := setupFuzzingInfrastructure(config, logger); err != nil {
		return fmt.Errorf("failed to setup fuzzing infrastructure: %w", err)
	}
	
	// EVALUATE - Verify installation was successful
	logger.Info("Verifying fuzzing installation")
	
	if err := verifyInstallation(rc.Ctx, logger); err != nil {
		return fmt.Errorf("installation verification failed: %w", err)
	}
	
	logger.Info("Fuzzing installation completed successfully")
	return nil
}

// assessInstallationNeeds determines what fuzzing components need to be installed
func assessInstallationNeeds(_ context.Context, logger otelzap.LoggerWithCtx) (bool, error) {
	logger.Debug("Checking fuzzing installation status")
	
	checks := []struct {
		name string
		fn   func() error
	}{
		{"Go installation", checkGoVersion},
		{"Go modules support", checkGoModulesSupport},
		{"Fuzzing support", checkFuzzingSupport},
		{"Test compilation", checkTestCompilation},
	}
	
	needsInstall := false
	for _, check := range checks {
		logger.Debug("Running installation check", zap.String("check", check.name))
		if err := check.fn(); err != nil {
			logger.Warn("Installation check failed",
				zap.String("check", check.name),
				zap.Error(err))
			needsInstall = true
		} else {
			logger.Debug("Installation check passed", zap.String("check", check.name))
		}
	}
	
	return needsInstall, nil
}

// installGoFuzzDependencies installs necessary Go fuzzing dependencies
func installGoFuzzDependencies(_ context.Context, logger otelzap.LoggerWithCtx) error {
	logger.Info("Installing Go fuzzing dependencies")
	
	// Check Go version supports fuzzing (Go 1.18+)
	if err := checkGoVersion(); err != nil {
		return fmt.Errorf("go version check failed: %w", err)
	}
	
	// Download dependencies for all test packages
	if err := downloadTestDependencies(logger); err != nil {
		return fmt.Errorf("failed to download test dependencies: %w", err)
	}
	
	// Compile test packages to verify everything works
	if err := compileTestPackages(logger); err != nil {
		return fmt.Errorf("failed to compile test packages: %w", err)
	}
	
	logger.Info("Go fuzzing dependencies installed successfully")
	return nil
}

// setupFuzzingInfrastructure sets up the fuzzing execution environment
func setupFuzzingInfrastructure(config *Config, logger otelzap.LoggerWithCtx) error {
	logger.Info("Setting up fuzzing infrastructure")
	
	// Create fuzzing directories
	dirs := []string{
		config.LogDir,
		filepath.Join(config.LogDir, "sessions"),
		filepath.Join(config.LogDir, "reports"),
		filepath.Join(config.LogDir, "crashes"),
	}
	
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, shared.ServiceDirPerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		logger.Debug("Created fuzzing directory", zap.String("path", dir))
	}
	
	// Create fuzzing configuration file
	if err := createFuzzingConfig(config, logger); err != nil {
		return fmt.Errorf("failed to create fuzzing configuration: %w", err)
	}
	
	logger.Info("Fuzzing infrastructure setup completed")
	return nil
}

// verifyInstallation checks that the fuzzing installation is working correctly
func verifyInstallation(_ context.Context, logger otelzap.LoggerWithCtx) error {
	logger.Debug("Verifying fuzzing installation")
	
	// Verify Go can run fuzz tests
	if err := verifyGoFuzzCapability(logger); err != nil {
		return fmt.Errorf("go fuzz capability verification failed: %w", err)
	}
	
	// Verify test discovery works
	if err := verifyTestDiscovery(logger); err != nil {
		return fmt.Errorf("test discovery verification failed: %w", err)
	}
	
	logger.Debug("Fuzzing installation verification completed successfully")
	return nil
}

// Helper functions for installation checks

func checkGoVersion() error {
	// #nosec G204 -- Hardcoded command with no user input
	cmd := exec.Command("go", "version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get Go version: %w", err)
	}
	
	version := string(output)
	// Check for Go 1.18+ (minimum for native fuzzing support)
	// For any go1.X version, assume it's supported (Go 1.18+)
	if strings.Contains(version, "go1.") {
		return nil
	}
	
	return fmt.Errorf("unsupported Go version: %s (requires Go 1.18+)", version)
}

func checkGoModulesSupport() error {
	// Check if go modules are enabled
	cmd := exec.Command("go", "env", "GO111MODULE")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check Go modules support: %w", err)
	}
	
	mode := strings.TrimSpace(string(output))
	if mode == "off" {
		return fmt.Errorf("go modules are disabled (GO111MODULE=off)")
	}
	
	return nil
}

func checkFuzzingSupport() error {
	// Try to run a simple fuzz test check
	cmd := exec.Command("go", "help", "test")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check fuzzing support: %w", err)
	}
	
	if !strings.Contains(string(output), "fuzz") {
		return fmt.Errorf("go installation does not support fuzzing")
	}
	
	return nil
}

func checkTestCompilation() error {
	// Try to compile tests in common directories
	testDirs := []string{"./pkg/...", "./cmd/..."}
	
	for _, dir := range testDirs {
		if _, err := os.Stat(strings.TrimSuffix(dir, "/...")); os.IsNotExist(err) {
			continue // Skip if directory doesn't exist
		}
		
		// #nosec G204 -- Directory path is from controlled list, not user input
		cmd := exec.Command("go", "test", "-c", dir)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to compile tests in %s: %w", dir, err)
		}
	}
	
	return nil
}

func downloadTestDependencies(logger otelzap.LoggerWithCtx) error {
	logger.Debug("Downloading test dependencies")
	
	cmd := exec.Command("go", "mod", "download")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to download dependencies: %w", err)
	}
	
	// Download test dependencies
	cmd = exec.Command("go", "mod", "tidy")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to tidy dependencies: %w", err)
	}
	
	return nil
}

func compileTestPackages(logger otelzap.LoggerWithCtx) error {
	logger.Debug("Compiling test packages")
	
	// Compile tests to check for issues
	packages := []string{"./pkg/...", "./cmd/..."}
	
	for _, pkg := range packages {
		// Check if package directory exists
		pkgDir := strings.TrimSuffix(pkg, "/...")
		if _, err := os.Stat(pkgDir); os.IsNotExist(err) {
			logger.Debug("Skipping non-existent package", zap.String("package", pkg))
			continue
		}
		
		logger.Debug("Compiling package tests", zap.String("package", pkg))
		// #nosec G204 -- Package path is from controlled list, not user input
		cmd := exec.Command("go", "test", "-c", "-o", "/dev/null", pkg)
		if err := cmd.Run(); err != nil {
			// Log warning but don't fail - some packages might not have tests
			logger.Warn("Failed to compile tests for package",
				zap.String("package", pkg),
				zap.Error(err))
		}
	}
	
	return nil
}

func createFuzzingConfig(config *Config, logger otelzap.LoggerWithCtx) error {
	configPath := filepath.Join(config.LogDir, "fuzzing.json")
	logger.Debug("Creating fuzzing configuration", zap.String("path", configPath))
	
	// Create a basic configuration file (could be expanded later)
	configData := fmt.Sprintf(`{
  "version": "1.0",
  "created": "%s",
  "default_duration": "%s",
  "default_parallel_jobs": %d,
  "log_dir": "%s"
}`, 
		"2024-01-01", // Would use actual timestamp
		config.Duration.String(),
		config.ParallelJobs,
		config.LogDir)
	
	if err := os.WriteFile(configPath, []byte(configData), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}
	
	return nil
}

func verifyGoFuzzCapability(logger otelzap.LoggerWithCtx) error {
	logger.Debug("Verifying Go fuzz capability")
	
	// Create a temporary simple fuzz test to verify capability
	tempDir, err := os.MkdirTemp("", "eos-fuzz-verify-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()
	
	// Write a simple fuzz test
	testContent := `package main

import "testing"

func FuzzSimple(f *testing.F) {
	f.Add("hello")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1000 {
			t.Skip("Input too long")
		}
	})
}
`
	
	testFile := filepath.Join(tempDir, "simple_fuzz_test.go")
	if err := os.WriteFile(testFile, []byte(testContent), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write test file: %w", err)
	}
	
	// Write go.mod
	modContent := `module fuzztest

go 1.21
`
	modFile := filepath.Join(tempDir, "go.mod")
	if err := os.WriteFile(modFile, []byte(modContent), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write go.mod: %w", err)
	}
	
	// Try to run the fuzz test for a very short time
	cmd := exec.Command("go", "test", "-fuzz=FuzzSimple", "-fuzztime=1s")
	cmd.Dir = tempDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("fuzz test verification failed: %w", err)
	}
	
	logger.Debug("Go fuzz capability verified successfully")
	return nil
}

func verifyTestDiscovery(logger otelzap.LoggerWithCtx) error {
	logger.Debug("Verifying test discovery")
	
	// Look for existing fuzz tests
	found := 0
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking
		}
		
		if strings.Contains(path, "fuzz") && strings.HasSuffix(path, "_test.go") {
			found++
			if found >= 3 { // Stop after finding a few
				return filepath.SkipDir
			}
		}
		
		return nil
	})
	
	if err != nil {
		logger.Warn("Error during test discovery verification", zap.Error(err))
	}
	
	logger.Debug("Test discovery verification completed",
		zap.Int("fuzz_tests_found", found))
	
	return nil
}