package saltstack

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Verifier handles Salt installation verification
type Verifier struct{}

// NewVerifier creates a new Salt verifier instance
func NewVerifier() *Verifier {
	return &Verifier{}
}

// Verify checks that Salt is properly installed and configured
func (v *Verifier) Verify(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Step 1: Verify Salt binary is available
	logger.Info("Verifying Salt binary")
	if err := v.verifySaltBinary(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("Salt binary verification failed: %w", err))
	}

	// Step 2: Verify configuration files exist
	logger.Info("Verifying configuration files")
	if err := v.verifyConfigFiles(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("configuration verification failed: %w", err))
	}

	// Step 3: Test Salt functionality with test state
	logger.Info("Testing Salt functionality")
	if err := v.testSaltFunctionality(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("Salt functionality test failed: %w", err))
	}

	// Step 4: Cleanup test artifacts
	logger.Info("Cleaning up test artifacts")
	if err := v.cleanupTestArtifacts(rc); err != nil {
		logger.Warn("Failed to cleanup test artifacts", zap.Error(err))
		// This is not fatal
	}

	logger.Info("Salt verification completed successfully")
	return nil
}

// verifySaltBinary checks that the salt-call command is available and working
func (v *Verifier) verifySaltBinary(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check salt-call version
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--version"},
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("salt-call command failed: %w", err)
	}

	if !strings.Contains(output, "salt-call") {
		return fmt.Errorf("unexpected salt-call version output: %s", output)
	}

	logger.Debug("Salt binary verified", zap.String("version", strings.TrimSpace(output)))

	// Test basic salt-call functionality
	logger.Debug("Testing basic salt-call functionality")
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "test.ping"},
		Timeout: 30 * time.Second,
	})

	if err != nil {
		return fmt.Errorf("salt-call test.ping failed: %w", err)
	}

	if !strings.Contains(output, "True") {
		return fmt.Errorf("salt-call test.ping returned unexpected result: %s", output)
	}

	logger.Debug("Basic Salt functionality verified")
	return nil
}

// verifyConfigFiles checks that all required configuration files exist
func (v *Verifier) verifyConfigFiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	requiredFiles := []string{
		MinionConfigPath,
	}

	requiredDirectories := []string{
		SaltStatesDir,
		EosStatesDir,
		SaltPillarDir,
	}

	// Check files
	for _, file := range requiredFiles {
		logger.Debug("Checking file", zap.String("path", file))

		stat, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("required file missing: %s", file)
		}

		if stat.IsDir() {
			return fmt.Errorf("expected file but found directory: %s", file)
		}

		if stat.Size() == 0 {
			return fmt.Errorf("required file is empty: %s", file)
		}
	}

	// Check directories
	for _, dir := range requiredDirectories {
		logger.Debug("Checking directory", zap.String("path", dir))

		stat, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("required directory missing: %s", dir)
		}

		if !stat.IsDir() {
			return fmt.Errorf("expected directory but found file: %s", dir)
		}
	}

	logger.Debug("All required files and directories verified")
	return nil
}

// testSaltFunctionality runs the test state to verify Salt is working
func (v *Verifier) testSaltFunctionality(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Run the test state
	logger.Info("Running Salt test state")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "state.apply", "eos.test"},
		Timeout: 60 * time.Second,
	})

	if err != nil {
		logger.Error("Test state execution failed",
			zap.Error(err),
			zap.String("output", output),
		)
		return fmt.Errorf("test state failed: %w", err)
	}

	// Check if the test state succeeded
	if !strings.Contains(output, "Succeeded: 2") || strings.Contains(output, "Failed:") {
		logger.Error("Test state did not complete successfully", zap.String("output", output))
		return fmt.Errorf("test state execution was not successful")
	}

	// Verify the test file was created
	testFilePath := "/tmp/eos-salt-test.txt"
	if _, err := os.Stat(testFilePath); err != nil {
		return fmt.Errorf("test file was not created: %s", testFilePath)
	}

	// Read and verify test file content
	content, err := os.ReadFile(testFilePath)
	if err != nil {
		return fmt.Errorf("failed to read test file: %w", err)
	}

	if !strings.Contains(string(content), "EOS Salt installation verified") {
		return fmt.Errorf("test file content is incorrect")
	}

	logger.Debug("Test state executed successfully",
		zap.String("output", output),
		zap.String("test_file", testFilePath),
	)

	return nil
}

// cleanupTestArtifacts removes files created during testing
func (v *Verifier) cleanupTestArtifacts(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	testFiles := []string{
		"/tmp/eos-salt-test.txt",
	}

	for _, file := range testFiles {
		logger.Debug("Removing test file", zap.String("path", file))

		if err := os.Remove(file); err != nil {
			if !os.IsNotExist(err) {
				logger.Warn("Failed to remove test file", zap.String("path", file), zap.Error(err))
			}
		}
	}

	return nil
}

// GetInstallationStatus returns the current Salt installation status
func (v *Verifier) GetInstallationStatus(rc *eos_io.RuntimeContext) (*InstallStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	status := &InstallStatus{
		LastChecked: time.Now(),
		ConfigPath:  MinionConfigPath,
		StatesPath:  EosStatesDir,
		PillarPath:  SaltPillarDir,
	}

	// Check if salt-call is available
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-call"},
		Timeout: 10 * time.Second,
	})

	if err != nil {
		status.Installed = false
		return status, nil
	}

	status.Installed = true

	// Get version
	versionOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--version"},
		Timeout: 10 * time.Second,
	})

	if err != nil {
		logger.Warn("Failed to get Salt version", zap.Error(err))
		status.Version = "unknown"
	} else {
		// Parse version from output
		if parts := strings.Fields(versionOutput); len(parts) >= 2 {
			status.Version = parts[1]
		} else {
			status.Version = "unknown"
		}
	}

	return status, nil
}
