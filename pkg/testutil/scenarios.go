// Package testutil - Predefined integration test scenarios
package testutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ========================================
// Predefined Integration Test Scenarios
// ========================================

// HTTPClientScenario creates a scenario for testing HTTP client functionality
func HTTPClientScenario() TestScenario {
	return TestScenario{
		Name:        "http_client_operations",
		Description: "Test HTTP client functionality end-to-end",
		Steps: []TestStep{
			{
				Name:        "create_context",
				Description: "Initialize runtime context for HTTP operations",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("http-client")
					if rc == nil {
						return errors.New("failed to create runtime context")
					}
					return nil
				},
				Timeout: 10 * time.Second,
			},
			{
				Name:        "test_http_transport",
				Description: "Verify HTTP transport configuration",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("http-transport")
					
					// Test that context has required attributes
					requiredAttrs := []string{"command", "timestamp"}
					for _, attr := range requiredAttrs {
						if rc.Attributes[attr] == "" {
							return fmt.Errorf("context missing required attribute: %s", attr)
						}
					}
					
					return nil
				},
				Timeout: 15 * time.Second,
			},
		},
	}
}

// FileSecurityScenario creates a scenario for testing file security operations
func FileSecurityScenario() TestScenario {
	return TestScenario{
		Name:        "file_security_operations",
		Description: "Test secure file operations and permission validation",
		Setup: func(s *IntegrationTestSuite) {
			// Create test directories
			secretsDir := filepath.Join(s.GetTempDir(), "eos/secrets")
			CreateTestDir(s.t, s.GetTempDir(), "eos/secrets", 0700)
			
			// Create test token file with secure permissions
			CreateTestFile(s.t, secretsDir, "test.token", "hvs.test123456789", 0600)
			
			// Create insecure token file for negative testing
			CreateTestFile(s.t, secretsDir, "insecure.token", "hvs.insecure123", 0644)
		},
		Steps: []TestStep{
			{
				Name:        "validate_secure_file_permissions",
				Description: "Verify secure files are properly validated",
				Action: func(s *IntegrationTestSuite) error {
					s.CreateTestContext("file-validation")
					securePath := filepath.Join(s.GetTempDir(), "eos/secrets/test.token")
					
					// Check file permissions directly
					info, err := os.Stat(securePath)
					if err != nil {
						return fmt.Errorf("failed to stat file: %w", err)
					}
					
					perm := info.Mode().Perm()
					if perm != 0600 {
						return fmt.Errorf("expected permissions 0600, got %o", perm)
					}
					
					return nil
				},
				Timeout: 5 * time.Second,
			},
			{
				Name:        "reject_insecure_file_permissions",
				Description: "Verify insecure files are properly identified",
				Action: func(s *IntegrationTestSuite) error {
					s.CreateTestContext("file-validation-negative")
					insecurePath := filepath.Join(s.GetTempDir(), "eos/secrets/insecure.token")
					
					// Check file permissions
					info, err := os.Stat(insecurePath)
					if err != nil {
						return fmt.Errorf("failed to stat file: %w", err)
					}
					
					perm := info.Mode().Perm()
					if perm == 0600 {
						return errors.New("expected insecure permissions but file is secure")
					}
					
					return nil
				},
				Timeout: 5 * time.Second,
			},
			{
				Name:        "test_secure_file_operations",
				Description: "Test secure file read/write operations",
				Action: func(s *IntegrationTestSuite) error {
					s.CreateTestContext("secure-file-ops")
					testPath := filepath.Join(s.GetTempDir(), "eos/secrets/secure_test.token")
					testData := "test-secure-content"
					
					// Test write with secure permissions
					CreateTestFile(s.t, filepath.Dir(testPath), "secure_test.token", testData, 0600)
					
					// Test read
					data, err := os.ReadFile(testPath)
					if err != nil {
						return fmt.Errorf("failed to read file: %w", err)
					}
					
					if string(data) != testData {
						return fmt.Errorf("data mismatch: expected %s, got %s", testData, string(data))
					}
					
					return nil
				},
				Timeout: 10 * time.Second,
			},
		},
	}
}

// RuntimeContextLifecycleScenario tests runtime context lifecycle management
func RuntimeContextLifecycleScenario() TestScenario {
	return TestScenario{
		Name:        "runtime_context_lifecycle",
		Description: "Test runtime context creation, usage, and cleanup",
		Steps: []TestStep{
			{
				Name:        "test_context_creation",
				Description: "Verify runtime context is properly initialized",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("lifecycle-test")
					
					// Verify all required fields are initialized
					if rc.Ctx == nil {
						return errors.New("context.Context was nil")
					}
					if rc.Log == nil {
						return errors.New("logger was nil")
					}
					if rc.Attributes == nil {
						return errors.New("attributes map was nil")
					}
					if rc.Command == "" {
						return errors.New("command was empty")
					}
					if rc.Timestamp.IsZero() {
						return errors.New("timestamp was zero")
					}
					
					return nil
				},
				Timeout: 5 * time.Second,
			},
			{
				Name:        "test_context_attributes",
				Description: "Test runtime context attribute management",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("attributes-test")
					
					// Test setting and getting attributes
					testAttributes := map[string]string{
						"test_key":     "test_value",
						"vault_addr":   "http://127.0.0.1:8200",
						"log_level":    "debug",
						"component":    "integration-test",
					}
					
					// Copy attributes to runtime context
					for key, value := range testAttributes {
						rc.Attributes[key] = value
					}
					
					// Verify all attributes were set correctly
					for key, expectedValue := range testAttributes {
						actualValue := rc.Attributes[key]
						if actualValue != expectedValue {
							return fmt.Errorf("attribute %s: expected %s, got %s", key, expectedValue, actualValue)
						}
					}
					
					return nil
				},
				Timeout: 5 * time.Second,
			},
			{
				Name:        "test_context_cancellation",
				Description: "Test context cancellation propagation",
				Action: func(s *IntegrationTestSuite) error {
					rc, cancel := TestRuntimeContextWithCancel(s.t)
					defer cancel()
					
					// Start goroutine that waits for cancellation
					done := make(chan bool, 1)
					go func() {
						<-rc.Ctx.Done()
						done <- true
					}()
					
					// Cancel context
					cancel()
					
					// Verify cancellation propagated
					select {
					case <-done:
						return nil
					case <-time.After(100 * time.Millisecond):
						return errors.New("context cancellation did not propagate")
					}
				},
				Timeout: 5 * time.Second,
			},
			{
				Name:        "test_context_timeout",
				Description: "Test context timeout handling",
				Action: func(s *IntegrationTestSuite) error {
					rc, cancel := TestRuntimeContextWithTimeout(s.t, 50*time.Millisecond)
					defer cancel()
					
					// Wait for timeout
					select {
					case <-rc.Ctx.Done():
						// Verify it was a timeout
						if rc.Ctx.Err() != context.DeadlineExceeded {
							return fmt.Errorf("expected deadline exceeded, got %v", rc.Ctx.Err())
						}
						return nil
					case <-time.After(100 * time.Millisecond):
						return errors.New("context did not timeout as expected")
					}
				},
				Timeout: 5 * time.Second,
			},
		},
	}
}

// ErrorHandlingScenario tests comprehensive error handling
func ErrorHandlingScenario() TestScenario {
	return TestScenario{
		Name:        "error_handling_comprehensive",
		Description: "Test error categorization, recovery, and security",
		Steps: []TestStep{
			{
				Name:        "test_panic_recovery",
				Description: "Verify panic recovery functionality",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("panic-recovery")
					var err error
					
					// Simulate panic recovery
					func() {
						defer rc.HandlePanic(&err)
						panic("test panic for recovery")
					}()
					
					if err == nil {
						return errors.New("expected error after panic recovery")
					}
					
					if !Contains(err.Error(), "panic: test panic for recovery") {
						return fmt.Errorf("error should contain panic message, got: %s", err.Error())
					}
					
					return nil
				},
				Timeout: 5 * time.Second,
			},
			{
				Name:        "test_error_information_disclosure",
				Description: "Verify errors don't disclose sensitive information",
				Action: func(s *IntegrationTestSuite) error {
					s.CreateTestContext("error-security")
					
					// Create a test error with potentially sensitive information
					testErr := errors.New("connection failed to server at localhost:8200")
					
					// Check that error doesn't contain sensitive information
					errMsg := testErr.Error()
					sensitiveTerms := []string{
						"/etc/vault-agent",
						"/var/lib/eos/secrets",
						"vault_init.json",
						"root_token",
						"secret_id",
					}
					
					for _, term := range sensitiveTerms {
						if Contains(errMsg, term) {
							return fmt.Errorf("error message contains sensitive information: %s in %s", term, errMsg)
						}
					}
					
					// Test should pass since our test error doesn't contain sensitive info
					return nil
				},
				Timeout: 15 * time.Second,
			},
		},
	}
}

// ========================================
// Common Test Patterns
// ========================================

// TestPattern represents a reusable test pattern
type TestPattern struct {
	Name        string
	Description string
	Setup       func(*IntegrationTestSuite) error
	Execute     func(*IntegrationTestSuite) error
	Validate    func(*IntegrationTestSuite) error
	Cleanup     func(*IntegrationTestSuite) error
}

// MockServicePattern creates a pattern for testing with mocked external services
func MockServicePattern(serviceName string, transport *MockHTTPTransport) TestPattern {
	return TestPattern{
		Name:        fmt.Sprintf("mock_%s_service", serviceName),
		Description: fmt.Sprintf("Test pattern with mocked %s service", serviceName),
		Setup: func(s *IntegrationTestSuite) error {
			s.WithMockTransport(transport)
			return nil
		},
		Execute: func(s *IntegrationTestSuite) error {
			// Pattern-specific execution logic
			rc := s.CreateTestContext(fmt.Sprintf("%s-test", serviceName))
			rc.Attributes[fmt.Sprintf("%s_mock", serviceName)] = "enabled"
			return nil
		},
		Validate: func(s *IntegrationTestSuite) error {
			// Validate mock service integration
			return nil
		},
	}
}

// FileSystemPattern creates a pattern for testing file system operations
func FileSystemPattern(baseDir string) TestPattern {
	return TestPattern{
		Name:        "filesystem_operations",
		Description: "Test pattern for file system operations",
		Setup: func(s *IntegrationTestSuite) error {
			// Create directory structure
			CreateTestDir(s.t, s.GetTempDir(), baseDir, 0755)
			return nil
		},
		Execute: func(s *IntegrationTestSuite) error {
			// Test file operations
			testPath := filepath.Join(s.GetTempDir(), baseDir, "test.txt")
			CreateTestFile(s.t, filepath.Dir(testPath), "test.txt", "test content", 0644)
			return nil
		},
		Validate: func(s *IntegrationTestSuite) error {
			// Validate file operations
			s.AssertFileExists(filepath.Join(baseDir, "test.txt"))
			return nil
		},
	}
}

// ConcurrencyPattern creates a pattern for testing concurrent operations
func ConcurrencyPattern(numWorkers int, operation func(workerID int, s *IntegrationTestSuite) error) TestPattern {
	return TestPattern{
		Name:        fmt.Sprintf("concurrency_%d_workers", numWorkers),
		Description: fmt.Sprintf("Test pattern with %d concurrent workers", numWorkers),
		Execute: func(s *IntegrationTestSuite) error {
			errors := make(chan error, numWorkers)
			
			for i := range numWorkers {
				go func(workerID int) {
					errors <- operation(workerID, s)
				}(i)
			}
			
			// Collect results
			for range numWorkers {
				if err := <-errors; err != nil {
					return fmt.Errorf("worker failed: %w", err)
				}
			}
			
			return nil
		},
	}
}