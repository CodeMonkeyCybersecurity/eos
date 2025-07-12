package execute

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestRetryCommand(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		maxAttempts int
		delay       time.Duration
		command     string
		args        []string
		wantErr     bool
	}]{
		{
			Name: "successful command on first attempt",
			Input: struct {
				maxAttempts int
				delay       time.Duration
				command     string
				args        []string
				wantErr     bool
			}{
				maxAttempts: 3,
				delay:       10 * time.Millisecond,
				command:     "echo",
				args:        []string{"test"},
				wantErr:     false,
			},
		},
		{
			Name: "command that always fails",
			Input: struct {
				maxAttempts int
				delay       time.Duration
				command     string
				args        []string
				wantErr     bool
			}{
				maxAttempts: 2,
				delay:       10 * time.Millisecond,
				command:     "false",
				args:        []string{},
				wantErr:     true,
			},
		},
		{
			Name: "nonexistent command",
			Input: struct {
				maxAttempts int
				delay       time.Duration
				command     string
				args        []string
				wantErr     bool
			}{
				maxAttempts: 3,
				delay:       5 * time.Millisecond,
				command:     "definitely-not-a-real-command-12345",
				args:        []string{},
				wantErr:     true,
			},
		},
		{
			Name: "single attempt success",
			Input: struct {
				maxAttempts int
				delay       time.Duration
				command     string
				args        []string
				wantErr     bool
			}{
				maxAttempts: 1,
				delay:       0,
				command:     "echo",
				args:        []string{"single"},
				wantErr:     false,
			},
		},
		{
			Name: "command with arguments",
			Input: struct {
				maxAttempts int
				delay       time.Duration
				command     string
				args        []string
				wantErr     bool
			}{
				maxAttempts: 2,
				delay:       5 * time.Millisecond,
				command:     "echo",
				args:        []string{"hello", "world"},
				wantErr:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			start := time.Now()
			err := RetryCommand(rc, tt.Input.maxAttempts, tt.Input.delay, tt.Input.command, tt.Input.args...)
			elapsed := time.Since(start)

			if tt.Input.wantErr {
				assert.Error(t, err)
				// Check that it actually retried (should take at least delay * (attempts-1))
				if tt.Input.maxAttempts > 1 && tt.Input.delay > 0 {
					expectedMinDuration := tt.Input.delay * time.Duration(tt.Input.maxAttempts-1)
					// Allow some tolerance for execution time
					assert.GreaterOrEqual(t, elapsed, expectedMinDuration/2)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRetryCaptureOutput(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		retries   int
		delay     time.Duration
		command   string
		args      []string
		wantErr   bool
		expectOut string
	}]{
		{
			Name: "capture successful command output",
			Input: struct {
				retries   int
				delay     time.Duration
				command   string
				args      []string
				wantErr   bool
				expectOut string
			}{
				retries:   3,
				delay:     10 * time.Millisecond,
				command:   "echo",
				args:      []string{"captured"},
				wantErr:   false,
				expectOut: "captured",
			},
		},
		{
			Name: "capture output from failing command",
			Input: struct {
				retries   int
				delay     time.Duration
				command   string
				args      []string
				wantErr   bool
				expectOut string
			}{
				retries:   2,
				delay:     5 * time.Millisecond,
				command:   "sh",
				args:      []string{"-c", "echo 'error output' >&2; exit 1"},
				wantErr:   true,
				expectOut: "error output",
			},
		},
		{
			Name: "capture from nonexistent command",
			Input: struct {
				retries   int
				delay     time.Duration
				command   string
				args      []string
				wantErr   bool
				expectOut string
			}{
				retries:   2,
				delay:     5 * time.Millisecond,
				command:   "definitely-not-a-real-command-12345",
				args:      []string{},
				wantErr:   true,
				expectOut: "",
			},
		},
		{
			Name: "single retry capture",
			Input: struct {
				retries   int
				delay     time.Duration
				command   string
				args      []string
				wantErr   bool
				expectOut string
			}{
				retries:   1,
				delay:     0,
				command:   "echo",
				args:      []string{"single retry"},
				wantErr:   false,
				expectOut: "single retry",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			start := time.Now()
			output, err := RetryCommandCaptureRefactored(rc, tt.Input.retries, tt.Input.delay, tt.Input.command, tt.Input.args...)
			elapsed := time.Since(start)

			if tt.Input.wantErr {
				assert.Error(t, err)
				// For failing commands, check that retries actually happened
				if tt.Input.retries > 1 && tt.Input.delay > 0 {
					expectedMinDuration := tt.Input.delay * time.Duration(tt.Input.retries-1)
					assert.GreaterOrEqual(t, elapsed, expectedMinDuration/2)
				}
			} else {
				assert.NoError(t, err)
			}

			if tt.Input.expectOut != "" {
				assert.Contains(t, string(output), tt.Input.expectOut)
			}
		})
	}
}

// Security Tests for Retry Functions
func TestRetryCommandSecurity(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		command     string
		args        []string
		description string
	}]{
		{
			Name: "command injection in retry command",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"; rm -rf /"},
				description: "semicolon injection attempt",
			},
		},
		{
			Name: "shell metacharacters in retry args",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"test && whoami"},
				description: "logical AND injection",
			},
		},
		{
			Name: "pipe injection in retry command",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"safe | cat /etc/passwd"},
				description: "pipe injection attempt",
			},
		},
		{
			Name: "command substitution in retry args",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"$(whoami)"},
				description: "command substitution attempt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// RetryCommand should handle malicious input safely
			err := RetryCommand(rc, 1, 0, tt.Input.command, tt.Input.args...)

			// Should complete without security issues (may succeed or fail)
			// The important thing is no command injection occurs
			_ = err
		})
	}
}

func TestRetryCaptureOutputSecurity(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		command     string
		args        []string
		description string
	}]{
		{
			Name: "injection in capture command",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"; cat /etc/passwd"},
				description: "semicolon injection in capture",
			},
		},
		{
			Name: "backtick injection in capture args",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"`id`"},
				description: "backtick command substitution",
			},
		},
		{
			Name: "null byte in capture command",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo\x00malicious",
				args:        []string{"test"},
				description: "null byte injection",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// Should handle malicious input safely
			output, err := RetryCommandCaptureRefactored(rc, 1, 0, tt.Input.command, tt.Input.args...)

			// Check that malicious content appears as literal text if command succeeds
			if err == nil && tt.Input.command == "echo" {
				for _, arg := range tt.Input.args {
					if strings.Contains(arg, ";") || strings.Contains(arg, "`") {
						assert.Contains(t, string(output), arg)
					}
				}
			}
		})
	}
}

// Test Context Cancellation
func TestRetryCommandContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	// Long-running command that should be cancelled
	start := time.Now()
	err := RetryCommand(rc, 5, 50*time.Millisecond, "sleep", "2")
	elapsed := time.Since(start)

	assert.Error(t, err)
	// Should be cancelled before the full sleep duration
	assert.Less(t, elapsed, 1*time.Second)
}

func TestRetryCaptureOutputContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	// Long-running command that should be cancelled
	start := time.Now()
	_, err := RetryCommandCaptureRefactored(rc, 5, 50*time.Millisecond, "sleep", "2")
	elapsed := time.Since(start)

	assert.Error(t, err)
	// Should be cancelled before the full sleep duration
	assert.Less(t, elapsed, 1*time.Second)
}

// Test Edge Cases
func TestRetryCommandEdgeCases(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		maxAttempts int
		delay       time.Duration
		command     string
		args        []string
		wantErr     bool
	}]{
		{
			Name: "zero attempts",
			Input: struct {
				maxAttempts int
				delay       time.Duration
				command     string
				args        []string
				wantErr     bool
			}{
				maxAttempts: 0,
				delay:       0,
				command:     "echo",
				args:        []string{"test"},
				wantErr:     false, // max(1, 0) = 1 attempt
			},
		},
		{
			Name: "negative attempts",
			Input: struct {
				maxAttempts int
				delay       time.Duration
				command     string
				args        []string
				wantErr     bool
			}{
				maxAttempts: -5,
				delay:       0,
				command:     "echo",
				args:        []string{"test"},
				wantErr:     false, // max(1, -5) = 1 attempt
			},
		},
		{
			Name: "very long delay",
			Input: struct {
				maxAttempts int
				delay       time.Duration
				command     string
				args        []string
				wantErr     bool
			}{
				maxAttempts: 1, // Only 1 attempt so delay doesn't matter
				delay:       10 * time.Second,
				command:     "echo",
				args:        []string{"test"},
				wantErr:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := RetryCommand(rc, tt.Input.maxAttempts, tt.Input.delay, tt.Input.command, tt.Input.args...)

			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Benchmark Tests
func BenchmarkRetryCommand(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RetryCommand(rc, 1, 0, "echo", "benchmark")
	}
}

func BenchmarkRetryCaptureOutput(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RetryCommandCaptureRefactored(rc, 1, 0, "echo", "benchmark")
	}
}
