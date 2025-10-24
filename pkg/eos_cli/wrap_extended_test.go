// pkg/eos_cli/wrap_extended_test.go

package eos_cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestWrapExtended(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		fn          func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error
		setupCmd    func() *cobra.Command
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:    "successful execution with custom timeout",
			timeout: 5 * time.Minute,
			fn: func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
				// Verify we got a runtime context
				assert.NotNil(t, rc)
				assert.NotNil(t, rc.Ctx)
				assert.NotNil(t, rc.Log)
				return nil
			},
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "test-cmd"}
			},
			args:        []string{"arg1", "arg2"},
			expectError: false,
		},
		{
			name:    "command returns error",
			timeout: 1 * time.Minute,
			fn: func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
				return errors.New("command failed")
			},
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "test-cmd"}
			},
			args:        []string{},
			expectError: true,
			errorMsg:    "command failed",
		},
		{
			name:    "panic recovery",
			timeout: 30 * time.Second,
			fn: func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
				panic("test panic")
			},
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "panic-cmd"}
			},
			args:        []string{},
			expectError: true,
			errorMsg:    "panic: test panic",
		},
		{
			name:    "sanitization with dangerous args",
			timeout: 1 * time.Minute,
			fn: func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
				// If sanitization works, args should be cleaned
				assert.NotContains(t, args, "../../../etc/passwd")
				return nil
			},
			setupCmd: func() *cobra.Command {
				// Use a non-sensitive command for this test
				cmd := &cobra.Command{Use: "test"}
				return cmd
			},
			args:        []string{"test\x00null"}, // Null bytes should fail sanitization
			expectError: true,
			errorMsg:    "null byte",
		},
		{
			name:    "extended timeout for long operations",
			timeout: 10 * time.Minute,
			fn: func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
				// Verify context has appropriate timeout
				deadline, ok := rc.Ctx.Deadline()
				if !ok {
					t.Error("Expected context to have deadline")
				}

				// Check timeout is approximately correct (within 1 second)
				expectedDeadline := time.Now().Add(10 * time.Minute)
				diff := deadline.Sub(expectedDeadline)
				if diff < -1*time.Second || diff > 1*time.Second {
					t.Errorf("Deadline mismatch: expected ~%v, got %v", expectedDeadline, deadline)
				}
				return nil
			},
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "long-running"}
			},
			args:        []string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.setupCmd()
			wrappedFn := WrapExtended(tt.timeout, tt.fn)

			err := wrappedFn(cmd, tt.args)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, but got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !assert.Contains(t, err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, but got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
			}
		})
	}
}

// TestSanitizeCommandInputs tests the sanitization function comprehensively
func TestSanitizeCommandInputsExtended(t *testing.T) {
	tests := []struct {
		name        string
		cmdName     string
		args        []string
		setupFlags  func(*cobra.Command)
		expectError bool
		errorMsg    string
	}{
		{
			name:    "path traversal in arguments",
			cmdName: "test",
			args:    []string{"../../../etc/passwd", "normal-arg"},
			setupFlags: func(cmd *cobra.Command) {
				// No flags
			},
			expectError: true,
			errorMsg:    "path traversal",
		},
		{
			name:    "null bytes in arguments",
			cmdName: "test",
			args:    []string{"test\x00null", "normal"},
			setupFlags: func(cmd *cobra.Command) {
				// No flags
			},
			expectError: true,
			errorMsg:    "null byte",
		},
		{
			name:    "sensitive command with strict validation",
			cmdName: "vault",
			args:    []string{"secret/data"},
			setupFlags: func(cmd *cobra.Command) {
				cmd.Flags().String("token", "valid-token", "token")
			},
			expectError: false,
		},
		{
			name:    "flag with path traversal",
			cmdName: "test",
			args:    []string{},
			setupFlags: func(cmd *cobra.Command) {
				cmd.Flags().String("file", "", "file path")
				_ = cmd.Flags().Set("file", "../../sensitive/file")
			},
			expectError: true,
			errorMsg:    "path traversal",
		},
		{
			name:    "SQL injection attempt",
			cmdName: "database",
			args:    []string{"'; DROP TABLE users; --"},
			setupFlags: func(cmd *cobra.Command) {
				// No flags
			},
			expectError: true,
			errorMsg:    "SQL injection",
		},
		{
			name:    "command injection in args",
			cmdName: "execute",
			args:    []string{"test; rm -rf /"},
			setupFlags: func(cmd *cobra.Command) {
				// No flags
			},
			expectError: true,
			errorMsg:    "command injection",
		},
		{
			name:    "very long argument",
			cmdName: "test",
			args:    []string{string(make([]byte, 10000))},
			setupFlags: func(cmd *cobra.Command) {
				// No flags
			},
			expectError: true,
			errorMsg:    "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := eos_io.NewContext(context.Background(), "test")
			cmd := &cobra.Command{Use: tt.cmdName}

			if tt.setupFlags != nil {
				tt.setupFlags(cmd)
			}

			sanitized, err := sanitizeCommandInputs(ctx, cmd, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, sanitized)
			}
		})
	}
}

// TestArgsModified tests the argsModified helper function
func TestArgsModified(t *testing.T) {
	tests := []struct {
		name     string
		original []string
		current  []string
		expected bool
	}{
		{
			name:     "identical args",
			original: []string{"arg1", "arg2"},
			current:  []string{"arg1", "arg2"},
			expected: false,
		},
		{
			name:     "different length",
			original: []string{"arg1", "arg2"},
			current:  []string{"arg1"},
			expected: true,
		},
		{
			name:     "different content",
			original: []string{"arg1", "arg2"},
			current:  []string{"arg1", "modified"},
			expected: true,
		},
		{
			name:     "both empty",
			original: []string{},
			current:  []string{},
			expected: false,
		},
		{
			name:     "nil vs empty",
			original: nil,
			current:  []string{},
			expected: false,
		},
		{
			name:     "order matters",
			original: []string{"arg1", "arg2"},
			current:  []string{"arg2", "arg1"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := argsModified(tt.original, tt.current)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestWrapExtendedIntegration tests the full integration
func TestWrapExtendedIntegration(t *testing.T) {
	t.Run("full command execution flow", func(t *testing.T) {
		executionSteps := []string{}

		fn := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			executionSteps = append(executionSteps, "function executed")

			// Verify context setup
			assert.NotNil(t, rc)
			assert.NotNil(t, rc.Ctx)
			assert.NotNil(t, rc.Log)
			assert.Equal(t, "integration-test", cmd.Name())
			assert.Equal(t, []string{"arg1", "arg2"}, args)

			// Check attributes
			assert.NotNil(t, rc.Attributes)

			return nil
		}

		cmd := &cobra.Command{Use: "integration-test"}
		wrapped := WrapExtended(2*time.Minute, fn)

		err := wrapped(cmd, []string{"arg1", "arg2"})

		assert.NoError(t, err)
		assert.Contains(t, executionSteps, "function executed")
	})

	t.Run("context cancellation", func(t *testing.T) {
		fn := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			// Simulate long-running operation
			select {
			case <-time.After(5 * time.Second):
				return errors.New("should have been cancelled")
			case <-rc.Ctx.Done():
				return rc.Ctx.Err()
			}
		}

		cmd := &cobra.Command{Use: "cancel-test"}
		// Use very short timeout to trigger cancellation
		wrapped := WrapExtended(10*time.Millisecond, fn)

		err := wrapped(cmd, []string{})

		// Should timeout
		assert.Error(t, err)
	})
}

// Benchmarks
func BenchmarkWrapExtended(b *testing.B) {
	fn := func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Minimal work
		return nil
	}

	cmd := &cobra.Command{Use: "bench-cmd"}
	wrapped := WrapExtended(1*time.Minute, fn)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wrapped(cmd, []string{"arg1", "arg2"})
	}
}

func BenchmarkSanitizeCommandInputs(b *testing.B) {
	ctx := eos_io.NewContext(context.Background(), "bench")
	cmd := &cobra.Command{Use: "bench-cmd"}
	args := []string{"normal", "args", "without", "issues"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sanitizeCommandInputs(ctx, cmd, args)
	}
}
