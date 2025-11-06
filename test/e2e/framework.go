//go:build e2e

// End-to-End Testing Framework for Eos
// Provides utilities for testing complete user workflows
package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// E2ETestSuite provides infrastructure for end-to-end testing
type E2ETestSuite struct {
	T          *testing.T
	Name       string
	WorkDir    string
	BinaryPath string
	RC         *eos_io.RuntimeContext
	Logger     otelzap.LoggerWithCtx
	Cleanup    []func()
}

// NewE2ETestSuite creates a new end-to-end test suite
func NewE2ETestSuite(t *testing.T, name string) *E2ETestSuite {
	t.Helper()

	// Create test runtime context
	rc := testutil.TestContext(t)
	logger := otelzap.Ctx(rc.Ctx)

	// Create temporary work directory
	workDir := t.TempDir()

	suite := &E2ETestSuite{
		T:       t,
		Name:    name,
		WorkDir: workDir,
		RC:      rc,
		Logger:  logger,
		Cleanup: []func(){},
	}

	// Find or build eos binary
	suite.BinaryPath = suite.findOrBuildBinary()

	return suite
}

// findOrBuildBinary locates the eos binary or builds it for testing
func (s *E2ETestSuite) findOrBuildBinary() string {
	s.T.Helper()

	// Check if binary already exists in /tmp
	tmpBinary := "/tmp/eos-test"
	if _, err := os.Stat(tmpBinary); err == nil {
		s.Logger.Info("Using existing test binary", zap.String("path", tmpBinary))
		return tmpBinary
	}

	// Build binary for testing
	s.Logger.Info("Building eos binary for E2E testing")

	// Determine project root (go up from test/e2e/ to root)
	projectRoot, err := filepath.Abs("../..")
	require.NoError(s.T, err, "failed to determine project root")

	buildCmd := exec.Command("go", "build", "-o", tmpBinary, "./cmd/")
	buildCmd.Dir = projectRoot
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	err = buildCmd.Run()
	require.NoError(s.T, err, "failed to build eos binary for E2E testing")

	s.Logger.Info("Built test binary", zap.String("path", tmpBinary))
	return tmpBinary
}

// RunCommand executes an eos command and returns output
func (s *E2ETestSuite) RunCommand(args ...string) *CommandResult {
	s.T.Helper()

	s.Logger.Info("Running eos command",
		zap.String("binary", s.BinaryPath),
		zap.Strings("args", args))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.BinaryPath, args...)
	cmd.Dir = s.WorkDir

	// Capture stdout and stderr
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	result := &CommandResult{
		Args:     args,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: cmd.ProcessState.ExitCode(),
		Error:    err,
		Duration: duration,
	}

	s.Logger.Info("Command completed",
		zap.Strings("args", args),
		zap.Int("exit_code", result.ExitCode),
		zap.Duration("duration", duration),
		zap.Bool("success", err == nil))

	if result.Stdout != "" {
		s.Logger.Debug("Command stdout", zap.String("output", result.Stdout))
	}
	if result.Stderr != "" {
		s.Logger.Debug("Command stderr", zap.String("output", result.Stderr))
	}

	return result
}

// CommandResult contains the results of running an eos command
type CommandResult struct {
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
	Error    error
	Duration time.Duration
}

// AssertSuccess asserts that the command succeeded (exit code 0)
func (r *CommandResult) AssertSuccess(t *testing.T) {
	t.Helper()
	require.NoError(t, r.Error, "command failed: %v\nStdout: %s\nStderr: %s",
		r.Error, r.Stdout, r.Stderr)
	require.Equal(t, 0, r.ExitCode, "command exited with non-zero status\nStdout: %s\nStderr: %s",
		r.Stdout, r.Stderr)
}

// AssertFails asserts that the command failed (exit code != 0)
func (r *CommandResult) AssertFails(t *testing.T) {
	t.Helper()
	require.NotEqual(t, 0, r.ExitCode, "expected command to fail but it succeeded\nStdout: %s\nStderr: %s",
		r.Stdout, r.Stderr)
}

// AssertContains asserts that stdout or stderr contains the given string
func (r *CommandResult) AssertContains(t *testing.T, substring string) {
	t.Helper()
	combined := r.Stdout + r.Stderr
	require.Contains(t, combined, substring, "output does not contain expected substring\nStdout: %s\nStderr: %s",
		r.Stdout, r.Stderr)
}

// AssertNotContains asserts that stdout and stderr do not contain the given string
func (r *CommandResult) AssertNotContains(t *testing.T, substring string) {
	t.Helper()
	combined := r.Stdout + r.Stderr
	require.NotContains(t, combined, substring, "output contains unexpected substring\nStdout: %s\nStderr: %s",
		r.Stdout, r.Stderr)
}

// RunWithTimeout runs a command with a custom timeout
func (s *E2ETestSuite) RunWithTimeout(timeout time.Duration, args ...string) *CommandResult {
	s.T.Helper()

	s.Logger.Info("Running eos command with timeout",
		zap.String("binary", s.BinaryPath),
		zap.Strings("args", args),
		zap.Duration("timeout", timeout))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.BinaryPath, args...)
	cmd.Dir = s.WorkDir

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	result := &CommandResult{
		Args:     args,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: cmd.ProcessState.ExitCode(),
		Error:    err,
		Duration: duration,
	}

	if ctx.Err() == context.DeadlineExceeded {
		s.Logger.Error("Command timed out",
			zap.Strings("args", args),
			zap.Duration("timeout", timeout))
		result.Error = fmt.Errorf("command timed out after %s", timeout)
	}

	return result
}

// CreateFile creates a file in the work directory
func (s *E2ETestSuite) CreateFile(path, content string) {
	s.T.Helper()

	fullPath := filepath.Join(s.WorkDir, path)
	dir := filepath.Dir(fullPath)

	err := os.MkdirAll(dir, 0755)
	require.NoError(s.T, err, "failed to create directory %s", dir)

	err = os.WriteFile(fullPath, []byte(content), 0644)
	require.NoError(s.T, err, "failed to write file %s", fullPath)

	s.Logger.Debug("Created test file",
		zap.String("path", fullPath),
		zap.Int("size", len(content)))
}

// FileExists checks if a file exists in the work directory
func (s *E2ETestSuite) FileExists(path string) bool {
	fullPath := filepath.Join(s.WorkDir, path)
	_, err := os.Stat(fullPath)
	return err == nil
}

// ReadFile reads a file from the work directory
func (s *E2ETestSuite) ReadFile(path string) string {
	s.T.Helper()

	fullPath := filepath.Join(s.WorkDir, path)
	content, err := os.ReadFile(fullPath)
	require.NoError(s.T, err, "failed to read file %s", fullPath)

	return string(content)
}

// AddCleanup adds a cleanup function to run at the end of the test
func (s *E2ETestSuite) AddCleanup(fn func()) {
	s.Cleanup = append(s.Cleanup, fn)
}

// RunCleanup runs all registered cleanup functions
func (s *E2ETestSuite) RunCleanup() {
	for i := len(s.Cleanup) - 1; i >= 0; i-- {
		s.Cleanup[i]()
	}
}

// SkipIfShort skips the test if -short flag is provided
func (s *E2ETestSuite) SkipIfShort(reason string) {
	if testing.Short() {
		s.T.Skipf("Skipping E2E test in short mode: %s", reason)
	}
}

// RequireRoot skips the test if not running as root
func (s *E2ETestSuite) RequireRoot(reason string) {
	if os.Geteuid() != 0 {
		s.T.Skipf("Skipping test (requires root): %s", reason)
	}
}

// WaitForCondition waits for a condition to become true
func (s *E2ETestSuite) WaitForCondition(condition func() bool, timeout time.Duration, description string) {
	s.T.Helper()

	s.Logger.Info("Waiting for condition",
		zap.String("description", description),
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			s.Logger.Info("Condition met", zap.String("description", description))
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	s.T.Fatalf("Timeout waiting for condition: %s", description)
}
