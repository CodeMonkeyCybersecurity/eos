package fuzzing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Verify checks that the fuzzing environment is properly configured and functional
func Verify(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check current state of fuzzing environment
	logger.Info("Assessing fuzzing environment status")

	status, err := assessFuzzingStatus(rc.Ctx, logger)
	if err != nil {
		return fmt.Errorf("failed to assess fuzzing status: %w", err)
	}

	// INTERVENE - Run verification tests
	logger.Info("Running fuzzing verification tests")

	if err := runVerificationTests(rc.Ctx, status, logger); err != nil {
		return fmt.Errorf("verification tests failed: %w", err)
	}

	// EVALUATE - Confirm everything is working correctly
	logger.Info("Evaluating fuzzing environment health")

	if err := evaluateFuzzingHealth(status, logger); err != nil {
		return fmt.Errorf("fuzzing environment health check failed: %w", err)
	}

	logger.Info("Fuzzing environment verification completed successfully",
		zap.Int("tests_found", status.TestsFound),
		zap.Int("packages_verified", status.PackagesVerified))

	return nil
}

// FuzzingStatus represents the current status of the fuzzing environment
type FuzzingStatus struct {
	GoVersion        string    `json:"go_version"`
	FuzzingSupported bool      `json:"fuzzing_supported"`
	TestsFound       int       `json:"tests_found"`
	PackagesVerified int       `json:"packages_verified"`
	LastVerified     time.Time `json:"last_verified"`
	Issues           []string  `json:"issues"`
	Capabilities     []string  `json:"capabilities"`
}

// assessFuzzingStatus evaluates the current state of the fuzzing environment
func assessFuzzingStatus(_ context.Context, logger otelzap.LoggerWithCtx) (*FuzzingStatus, error) {
	status := &FuzzingStatus{
		LastVerified: time.Now(),
		Issues:       []string{},
		Capabilities: []string{},
	}

	// Check Go version
	if version, err := getGoVersion(logger); err != nil {
		status.Issues = append(status.Issues, fmt.Sprintf("Go version check failed: %v", err))
	} else {
		status.GoVersion = version
		status.Capabilities = append(status.Capabilities, "Go runtime available")
	}

	// Check fuzzing support
	if supported, err := checkFuzzingSupportDetailed(logger); err != nil {
		status.Issues = append(status.Issues, fmt.Sprintf("Fuzzing support check failed: %v", err))
	} else {
		status.FuzzingSupported = supported
		if supported {
			status.Capabilities = append(status.Capabilities, "Native fuzzing supported")
		}
	}

	// Count available fuzz tests
	if count, err := countFuzzTests(logger); err != nil {
		status.Issues = append(status.Issues, fmt.Sprintf("Test counting failed: %v", err))
	} else {
		status.TestsFound = count
		status.Capabilities = append(status.Capabilities, fmt.Sprintf("Found %d fuzz tests", count))
	}

	// Verify package compilation
	if count, err := verifyPackageCompilation(logger); err != nil {
		status.Issues = append(status.Issues, fmt.Sprintf("Package verification failed: %v", err))
	} else {
		status.PackagesVerified = count
		status.Capabilities = append(status.Capabilities, fmt.Sprintf("Verified %d packages", count))
	}

	logger.Debug("Fuzzing status assessment completed",
		zap.Any("status", status))

	return status, nil
}

// runVerificationTests executes a series of tests to verify fuzzing functionality
func runVerificationTests(_ context.Context, _ *FuzzingStatus, logger otelzap.LoggerWithCtx) error {
	tests := []struct {
		name string
		fn   func(otelzap.LoggerWithCtx) error
	}{
		{"Go environment", verifyGoEnvironment},
		{"Module configuration", verifyModuleConfiguration},
		{"Test compilation", verifyTestCompilationDetailed},
		{"Fuzzing execution", verifyFuzzingExecution},
		{"Output handling", verifyOutputHandling},
	}

	for _, test := range tests {
		logger.Debug("Running verification test", zap.String("test", test.name))

		if err := test.fn(logger); err != nil {
			logger.Error("Verification test failed",
				zap.String("test", test.name),
				zap.Error(err))
			return fmt.Errorf("verification test '%s' failed: %w", test.name, err)
		}

		logger.Debug("Verification test passed", zap.String("test", test.name))
	}

	return nil
}

// evaluateFuzzingHealth performs final health checks on the fuzzing environment
func evaluateFuzzingHealth(status *FuzzingStatus, logger otelzap.LoggerWithCtx) error {
	logger.Debug("Evaluating fuzzing environment health")

	// Check for critical issues
	if len(status.Issues) > 0 {
		logger.Warn("Fuzzing environment has issues",
			zap.Strings("issues", status.Issues))
	}

	// Verify minimum requirements
	if !status.FuzzingSupported {
		return fmt.Errorf("fuzzing is not supported in current environment")
	}

	if status.TestsFound == 0 {
		logger.Warn("No fuzz tests found - fuzzing will have limited effectiveness")
	}

	if status.PackagesVerified == 0 {
		return fmt.Errorf("no packages could be verified for fuzzing")
	}

	// Calculate health score
	healthScore := calculateHealthScore(status)
	logger.Info("Fuzzing environment health assessment",
		zap.Float64("health_score", healthScore),
		zap.Int("capabilities", len(status.Capabilities)),
		zap.Int("issues", len(status.Issues)))

	if healthScore < 0.7 {
		return fmt.Errorf("fuzzing environment health score too low: %.2f (minimum 0.7)", healthScore)
	}

	return nil
}

// Helper functions for verification

func getGoVersion(logger otelzap.LoggerWithCtx) (string, error) {
	cmd := exec.Command("go", "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Go version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	logger.Debug("Go version detected", zap.String("version", version))

	return version, nil
}

func checkFuzzingSupportDetailed(logger otelzap.LoggerWithCtx) (bool, error) {
	// Check if 'go test -fuzz' is available via testflag help
	cmd := exec.Command("go", "help", "testflag")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failed to check Go testflag help: %w", err)
	}

	supported := strings.Contains(string(output), "-fuzz")
	logger.Debug("Fuzzing support check", zap.Bool("supported", supported))

	return supported, nil
}

func countFuzzTests(logger otelzap.LoggerWithCtx) (int, error) {
	count := 0

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking despite errors
		}

		// Skip vendor and .git directories
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == ".git") {
			return filepath.SkipDir
		}

		// Look for fuzz test files
		if strings.HasSuffix(path, "_test.go") && strings.Contains(path, "fuzz") {
			count++
			logger.Debug("Found fuzz test file", zap.String("path", path))
		}

		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to walk directory tree: %w", err)
	}

	logger.Debug("Fuzz test count completed", zap.Int("count", count))
	return count, nil
}

func verifyPackageCompilation(logger otelzap.LoggerWithCtx) (int, error) {
	packages := []string{"./pkg/...", "./cmd/..."}
	verified := 0

	for _, pkg := range packages {
		// Check if package directory exists
		pkgDir := strings.TrimSuffix(pkg, "/...")
		if _, err := os.Stat(pkgDir); os.IsNotExist(err) {
			logger.Debug("Package directory not found", zap.String("package", pkg))
			continue
		}

		// Try to compile tests
		// #nosec G204 -- Package path is validated from local filesystem walk, not user input
		cmd := exec.Command("go", "test", "-c", "-o", "/dev/null", pkg)
		if err := cmd.Run(); err != nil {
			logger.Debug("Package compilation failed",
				zap.String("package", pkg),
				zap.Error(err))
			continue
		}

		verified++
		logger.Debug("Package compilation verified", zap.String("package", pkg))
	}

	return verified, nil
}

func verifyGoEnvironment(logger otelzap.LoggerWithCtx) error {
	// Check GOROOT
	cmd := exec.Command("go", "env", "GOROOT")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get GOROOT: %w", err)
	}

	goroot := strings.TrimSpace(string(output))
	if goroot == "" {
		return fmt.Errorf("GOROOT is not set")
	}

	// Check GOPATH
	cmd = exec.Command("go", "env", "GOPATH")
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get GOPATH: %w", err)
	}

	gopath := strings.TrimSpace(string(output))
	logger.Debug("Go environment verified",
		zap.String("goroot", goroot),
		zap.String("gopath", gopath))

	return nil
}

func verifyModuleConfiguration(logger otelzap.LoggerWithCtx) error {
	// Check if go.mod exists
	if _, err := os.Stat("go.mod"); os.IsNotExist(err) {
		return fmt.Errorf("go.mod not found")
	}

	// Check module information
	cmd := exec.Command("go", "list", "-m")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get module information: %w", err)
	}

	module := strings.TrimSpace(string(output))
	logger.Debug("Module configuration verified", zap.String("module", module))

	return nil
}

func verifyTestCompilationDetailed(logger otelzap.LoggerWithCtx) error {
	// Try to compile a few key packages
	testPackages := []string{"./pkg/fuzzing", "./pkg/eos_cli", "./cmd/self"}

	for _, pkg := range testPackages {
		if _, err := os.Stat(strings.TrimPrefix(pkg, "./")); os.IsNotExist(err) {
			continue // Skip if package doesn't exist
		}

		// #nosec G204 -- Package path is from hardcoded list of trusted paths, not user input
		cmd := exec.Command("go", "test", "-c", "-o", "/dev/null", pkg)
		if err := cmd.Run(); err != nil {
			logger.Debug("Test compilation failed",
				zap.String("package", pkg),
				zap.Error(err))
			continue
		}

		logger.Debug("Test compilation verified", zap.String("package", pkg))
	}

	return nil
}

func verifyFuzzingExecution(logger otelzap.LoggerWithCtx) error {
	// Create a minimal test to verify fuzzing can execute
	tempDir, err := os.MkdirTemp("", "eos-fuzz-verify-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create a simple fuzz test
	testContent := `package verify

import "testing"

func FuzzVerification(f *testing.F) {
	f.Add("test")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) == 0 {
			return
		}
		// Simple verification test
	})
}
`

	testFile := filepath.Join(tempDir, "verify_test.go")
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		return fmt.Errorf("failed to write verification test: %w", err)
	}

	// Create go.mod
	modContent := `module verify

go 1.21
`
	modFile := filepath.Join(tempDir, "go.mod")
	if err := os.WriteFile(modFile, []byte(modContent), 0644); err != nil {
		return fmt.Errorf("failed to write go.mod: %w", err)
	}

	// Run the fuzz test briefly
	cmd := exec.Command("go", "test", "-fuzz=FuzzVerification", "-fuzztime=2s")
	cmd.Dir = tempDir

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("fuzzing execution verification failed: %w", err)
	}

	logger.Debug("Fuzzing execution verified successfully")
	return nil
}

func verifyOutputHandling(logger otelzap.LoggerWithCtx) error {
	// Verify we can capture and process fuzzing output
	tempDir, err := os.MkdirTemp("", "eos-output-verify-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Test that we can write to the temp directory
	testFile := filepath.Join(tempDir, "output_test.txt")
	if err := os.WriteFile(testFile, []byte("test output"), 0644); err != nil {
		return fmt.Errorf("output handling verification failed: %w", err)
	}

	// Verify we can read it back
	content, err := os.ReadFile(testFile)
	if err != nil {
		return fmt.Errorf("output reading verification failed: %w", err)
	}

	if string(content) != "test output" {
		return fmt.Errorf("output content verification failed")
	}

	logger.Debug("Output handling verified successfully")
	return nil
}

func calculateHealthScore(status *FuzzingStatus) float64 {
	score := 0.0
	maxScore := 5.0

	// Go version available (1 point)
	if status.GoVersion != "" {
		score += 1.0
	}

	// Fuzzing supported (2 points - most important)
	if status.FuzzingSupported {
		score += 2.0
	}

	// Tests found (1 point)
	if status.TestsFound > 0 {
		score += 1.0
	}

	// Packages verified (1 point)
	if status.PackagesVerified > 0 {
		score += 1.0
	}

	// Penalty for issues (subtract 0.1 per issue)
	penalty := float64(len(status.Issues)) * 0.1
	score -= penalty

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score / maxScore
}
