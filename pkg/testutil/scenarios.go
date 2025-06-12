// Package testutil - Predefined integration test scenarios
package testutil

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// ========================================
// Predefined Integration Test Scenarios
// ========================================

// VaultHealthCheckScenario creates a scenario for testing vault health checks
func VaultHealthCheckScenario() TestScenario {
	return TestScenario{
		Name:        "vault_health_check",
		Description: "Test vault health check functionality end-to-end",
		Steps: []TestStep{
			{
				Name:        "create_vault_client",
				Description: "Initialize vault client with test configuration",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("vault-health")
					_, err := vault.NewClient(rc)
					return err
				},
				Timeout: 10 * time.Second,
			},
			{
				Name:        "check_authentication_status",
				Description: "Verify authentication status checking works",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("vault-status")
					client, err := vault.NewClient(rc)
					if err != nil {
						return err
					}
					
					status := vault.GetAuthenticationStatus(rc, client)
					if status == nil {
						return errors.New("authentication status was nil")
					}
					
					// Verify required fields exist
					requiredFields := []string{"authenticated", "token_present", "token_valid", "timestamp"}
					for _, field := range requiredFields {
						if _, exists := status[field]; !exists {
							return fmt.Errorf("authentication status missing required field: %s", field)
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
					rc := s.CreateTestContext("file-validation")
					securePath := filepath.Join(s.GetTempDir(), "eos/secrets/test.token")
					return vault.ValidateTokenFilePermissions(rc, securePath)
				},
				Timeout: 5 * time.Second,
			},
			{
				Name:        "reject_insecure_file_permissions",
				Description: "Verify insecure files are properly rejected",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("file-validation-negative")
					insecurePath := filepath.Join(s.GetTempDir(), "eos/secrets/insecure.token")
					err := vault.ValidateTokenFilePermissions(rc, insecurePath)
					if err == nil {
						return errors.New("expected validation to fail for insecure file permissions")
					}
					return nil // Success if validation failed as expected
				},
				Timeout: 5 * time.Second,
			},
			{
				Name:        "test_secure_token_operations",
				Description: "Test secure token file read/write operations",
				Action: func(s *IntegrationTestSuite) error {
					rc := s.CreateTestContext("secure-token-ops")
					testPath := filepath.Join(s.GetTempDir(), "eos/secrets/secure_test.token")
					testToken := "hvs.AQAAAQAAAQAAAQAAAQAAAQAAAQAAAQAAAQAAAQAAAQAAAQAAAQAAAQAAAQAAAQ"
					
					// Test secure write
					err := vault.SecureWriteTokenFile(rc, testPath, testToken)
					if err != nil {
						return fmt.Errorf("secure write failed: %w", err)
					}
					
					// Test secure read
					readToken, err := vault.SecureReadTokenFile(rc, testPath)
					if err != nil {
						return fmt.Errorf("secure read failed: %w", err)
					}
					
					if readToken != testToken {
						return fmt.Errorf("token mismatch: expected %s, got %s", testToken, readToken)
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
					rc := s.CreateTestContext("error-security")
					client, err := vault.NewClient(rc)
					if err != nil {
						return err
					}
					
					// Try authentication that should fail
					err = vault.SecureAuthenticationOrchestrator(rc, client)
					if err == nil {
						return errors.New("expected authentication to fail in test environment")
					}
					
					// Check that error doesn't contain sensitive information
					errMsg := err.Error()
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
			
			for i := 0; i < numWorkers; i++ {
				go func(workerID int) {
					errors <- operation(workerID, s)
				}(i)
			}
			
			// Collect results
			for i := 0; i < numWorkers; i++ {
				if err := <-errors; err != nil {
					return fmt.Errorf("worker %d failed: %w", i, err)
				}
			}
			
			return nil
		},
	}
}