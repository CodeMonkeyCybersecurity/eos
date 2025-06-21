// Package testutil - Integration testing framework for Eos
package testutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/spf13/cobra"
)

// IntegrationTestSuite provides orchestration for complex integration tests
type IntegrationTestSuite struct {
	t                *testing.T
	tempDir          string
	cleanupFunctions []func()
	contexts         []*eos_io.RuntimeContext
	mutex            sync.Mutex
}

// NewIntegrationTestSuite creates a new integration testing environment
func NewIntegrationTestSuite(t *testing.T, suiteName string) *IntegrationTestSuite {
	t.Helper()

	// Initialize telemetry for integration tests
	err := telemetry.Init("eos-integration-test-" + suiteName)
	if err != nil {
		t.Fatalf("Failed to initialize telemetry: %v", err)
	}

	suite := &IntegrationTestSuite{
		t:                t,
		tempDir:          TempDir(t),
		cleanupFunctions: make([]func(), 0),
		contexts:         make([]*eos_io.RuntimeContext, 0),
	}

	// Setup comprehensive test environment
	suite.setupEnvironment()

	// Register cleanup
	t.Cleanup(func() {
		suite.Cleanup()
	})

	return suite
}

// setupEnvironment configures a complete test environment
func (s *IntegrationTestSuite) setupEnvironment() {
	s.t.Helper()

	// Create directory structure
	dirs := []string{
		"vault/tls",
		"vault/data",
		"eos/secrets",
		"eos/config",
		"logs",
		"tmp",
	}

	for _, dir := range dirs {
		fullPath := filepath.Join(s.tempDir, dir)
		err := os.MkdirAll(fullPath, 0755)
		if err != nil {
			s.t.Fatalf("Failed to create test directory %s: %v", fullPath, err)
		}
	}

	// Create mock TLS certificate
	s.createMockCertificate()

	// Set environment variables
	s.setTestEnvironment()
}

// createMockCertificate creates a valid test certificate
func (s *IntegrationTestSuite) createMockCertificate() {
	s.t.Helper()

	// Valid self-signed certificate for testing
	mockCert := `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUDthK1uy3dc6zXmAMlADQiy3G8ewwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDYxMjE0NTEwNloXDTI1MDYx
MzE0NTEwNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAw4CxDfz819erUBsDik9NVr3DNG8+kQgRKh3V68QdOEyr
B6/3j2TcJ6pzRYC+ddYK9FqG7M3V79M2BOXjhy9PoiUpYgkKq9JHDYNon+sVqASy
3lYl1UZlhsKA3ZMxMJPYG2EatAGzzoohYPB1UGFMG/heLF3Sy3rqPxqfT1MYsMRC
hnLcbgxRpYfBeZPnOoduF7PKaXQP+NA8QT4DoQxOWA7YIfbLjM0qrtoV5Xue3aOw
kaWuQ7taO4KOfOOJmZUH+aswQneP26NxfzdMGje0NPa+7SYV8NKazJMzIfCL7WAF
I9snb/xfWfiAo1/H7pI9Bx3uLfqMy2sgV/Fvvbm1bQIDAQABo1MwUTAdBgNVHQ4E
FgQUrPFmuROlNI+pmxIUY0KQA0cYAfswHwYDVR0jBBgwFoAUrPFmuROlNI+pmxIU
Y0KQA0cYAfswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFgSi
n6OBgl69JL3zNWl3YcRY/HQ1MZpiIgvNvALl9IrbJK4QNbmuYeZDd2IwP+p1a+Bk
w8NtjliSz3UCWfERSGYcKpLF7AcdFp+hIf6fMJSGlCqYTJfeW3rHIQgk4uocn4hh
oDQY6YmJSwGMsGEyaQu8MDvbyNfsnvALbuBNWOycrfa2g1e0nWLvUmuTnH6Mn71Y
bHREQkCDRUnW2vvK0o0nHeqUJcXYtTegHX99pdFtE8dVnpC4foR9Dyk20doAT9Fx
aRb6WpY/8lQZd+gx109OS2I6tKn9DyYw+fwZ+k+lMMS4lF1YnJuTU5LTRTOfDrOJ
2r1YWem6gtYoT7Enxg==
-----END CERTIFICATE-----`

	certPath := filepath.Join(s.tempDir, "vault/tls/tls.crt")
	err := os.WriteFile(certPath, []byte(mockCert), 0644)
	if err != nil {
		s.t.Fatalf("Failed to create mock certificate: %v", err)
	}
}

// setTestEnvironment configures environment variables for testing
func (s *IntegrationTestSuite) setTestEnvironment() {
	s.t.Helper()

	// Store original values for cleanup
	envVars := map[string]string{
		"EOS_TEST_MODE":     "true",
		"VAULT_SKIP_VERIFY": "true",
		"VAULT_CACERT":      filepath.Join(s.tempDir, "vault/tls/tls.crt"),
		shared.VaultAddrEnv: "http://127.0.0.1:8200",
		"EOS_DATA_DIR":      filepath.Join(s.tempDir, "eos"),
		"EOS_LOG_LEVEL":     "debug",
		"EOS_LOG_PATH":      filepath.Join(s.tempDir, "logs/eos.log"),
	}

	originalValues := make(map[string]string)
	for key, value := range envVars {
		originalValues[key] = os.Getenv(key)
		if err := os.Setenv(key, value); err != nil {
			s.t.Fatalf("Failed to set environment variable %s: %v", key, err)
		}
	}

	// Register cleanup to restore original environment
	s.AddCleanup(func() {
		for key, originalValue := range originalValues {
			if originalValue == "" {
				if err := os.Unsetenv(key); err != nil {
					// Log the error but don't fail cleanup
					s.t.Logf("Failed to unset environment variable %s: %v", key, err)
				}
			} else {
				if err := os.Setenv(key, originalValue); err != nil {
					// Log the error but don't fail cleanup
					s.t.Logf("Failed to restore environment variable %s: %v", key, err)
				}
			}
		}
	})
}

// CreateTestContext creates a runtime context for integration testing
func (s *IntegrationTestSuite) CreateTestContext(commandName string) *eos_io.RuntimeContext {
	s.t.Helper()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	ctx := context.Background()
	rc := eos_io.NewContext(ctx, commandName)

	// Track for cleanup
	s.contexts = append(s.contexts, rc)

	return rc
}

// WithMockTransport sets up mock HTTP transport for the test suite
func (s *IntegrationTestSuite) WithMockTransport(transport *MockHTTPTransport) {
	s.t.Helper()
	cleanup := WithMockHTTPClient(s.t, transport)
	s.AddCleanup(cleanup)
}

// WithVaultMock sets up a complete mock Vault environment
func (s *IntegrationTestSuite) WithVaultMock() {
	s.t.Helper()
	s.WithMockTransport(VaultMockTransport())
}

// WithDockerMock sets up a complete mock Docker environment
func (s *IntegrationTestSuite) WithDockerMock() {
	s.t.Helper()
	s.WithMockTransport(DockerMockTransport())
}

// AddCleanup adds a cleanup function to be called when the suite is torn down
func (s *IntegrationTestSuite) AddCleanup(cleanup func()) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.cleanupFunctions = append(s.cleanupFunctions, cleanup)
}

// Cleanup performs teardown of the integration test suite
func (s *IntegrationTestSuite) Cleanup() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// End all runtime contexts
	for _, rc := range s.contexts {
		if rc != nil {
			var err error
			rc.End(&err) // End the context gracefully
		}
	}

	// Run all cleanup functions in reverse order
	for i := len(s.cleanupFunctions) - 1; i >= 0; i-- {
		if s.cleanupFunctions[i] != nil {
			s.cleanupFunctions[i]()
		}
	}
}

// GetTempDir returns the temporary directory for this test suite
func (s *IntegrationTestSuite) GetTempDir() string {
	return s.tempDir
}

// ========================================
// Integration Test Scenarios
// ========================================

// TestScenario represents a complete end-to-end test scenario
type TestScenario struct {
	Name        string
	Description string
	Setup       func(*IntegrationTestSuite)
	Steps       []TestStep
	Cleanup     func(*IntegrationTestSuite)
}

// TestStep represents a single step in an integration test scenario
type TestStep struct {
	Name        string
	Description string
	Action      func(*IntegrationTestSuite) error
	Validation  func(*IntegrationTestSuite) error
	Timeout     time.Duration
}

// RunScenario executes a complete test scenario
func (s *IntegrationTestSuite) RunScenario(scenario TestScenario) {
	s.t.Helper()
	s.t.Run(scenario.Name, func(t *testing.T) {
		t.Helper()

		// Run setup if provided
		if scenario.Setup != nil {
			scenario.Setup(s)
		}

		// Run cleanup if provided
		if scenario.Cleanup != nil {
			defer scenario.Cleanup(s)
		}

		// Execute each step
		for i, step := range scenario.Steps {
			stepName := fmt.Sprintf("step_%d_%s", i+1, step.Name)
			t.Run(stepName, func(t *testing.T) {
				t.Helper()

				// Set timeout for step
				timeout := step.Timeout
				if timeout == 0 {
					timeout = 30 * time.Second // Default timeout
				}

				// Create context with timeout
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()

				// Execute step action
				done := make(chan error, 1)
				go func() {
					done <- step.Action(s)
				}()

				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("Step %s failed: %v", step.Name, err)
					}
				case <-ctx.Done():
					t.Fatalf("Step %s timed out after %v", step.Name, timeout)
				}

				// Run validation if provided
				if step.Validation != nil {
					done = make(chan error, 1)
					go func() {
						done <- step.Validation(s)
					}()

					select {
					case err := <-done:
						if err != nil {
							t.Fatalf("Step %s validation failed: %v", step.Name, err)
						}
					case <-ctx.Done():
						t.Fatalf("Step %s validation timed out after %v", step.Name, timeout)
					}
				}
			})
		}
	})
}

// ========================================
// Command Execution Utilities
// ========================================

// ExecuteCommand executes a Cobra command in the test environment
func (s *IntegrationTestSuite) ExecuteCommand(cmd *cobra.Command, args []string) error {
	s.t.Helper()

	// Set up command args
	cmd.SetArgs(args)

	// Capture output
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	// Execute the command
	return cmd.Execute()
}

// ExecuteCommandWithTimeout executes a command with a specified timeout
func (s *IntegrationTestSuite) ExecuteCommandWithTimeout(cmd *cobra.Command, args []string, timeout time.Duration) error {
	s.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- s.ExecuteCommand(cmd, args)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("command execution timed out after %v", timeout)
	}
}

// ========================================
// Assertion Helpers for Integration Tests
// ========================================

// AssertCommandSuccess asserts that a command executes successfully
func (s *IntegrationTestSuite) AssertCommandSuccess(cmd *cobra.Command, args []string) {
	s.t.Helper()
	err := s.ExecuteCommand(cmd, args)
	if err != nil {
		s.t.Fatalf("Command execution failed: %v", err)
	}
}

// AssertCommandFails asserts that a command fails with an error
func (s *IntegrationTestSuite) AssertCommandFails(cmd *cobra.Command, args []string) {
	s.t.Helper()
	err := s.ExecuteCommand(cmd, args)
	if err == nil {
		s.t.Fatal("Expected command to fail, but it succeeded")
	}
}

// AssertFileExists verifies that a file exists in the test environment
func (s *IntegrationTestSuite) AssertFileExists(relativePath string) {
	s.t.Helper()
	fullPath := filepath.Join(s.tempDir, relativePath)
	AssertFileExists(s.t, fullPath)
}

// AssertFileNotExists verifies that a file does not exist in the test environment
func (s *IntegrationTestSuite) AssertFileNotExists(relativePath string) {
	s.t.Helper()
	fullPath := filepath.Join(s.tempDir, relativePath)
	AssertFileNotExists(s.t, fullPath)
}

// AssertFileContent verifies file content in the test environment
func (s *IntegrationTestSuite) AssertFileContent(relativePath, expectedContent string) {
	s.t.Helper()
	fullPath := filepath.Join(s.tempDir, relativePath)
	AssertFileContent(s.t, fullPath, expectedContent)
}
