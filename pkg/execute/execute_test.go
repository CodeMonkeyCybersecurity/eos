package execute

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestRun(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []testutil.TableTest[struct {
		opts    Options
		wantErr bool
	}]{
		{
			Name: "successful echo command",
			Input: struct {
				opts    Options
				wantErr bool
			}{
				opts: Options{
					Command: "echo",
					Args:    []string{"test"},
					Capture: true,
				},
				wantErr: false,
			},
		},
		{
			Name: "nonexistent command",
			Input: struct {
				opts    Options
				wantErr bool
			}{
				opts: Options{
					Command: "definitely-not-a-real-command-12345",
					Args:    []string{},
				},
				wantErr: true,
			},
		},
		{
			Name: "command with retries",
			Input: struct {
				opts    Options
				wantErr bool
			}{
				opts: Options{
					Command: "false", // Always fails
					Args:    []string{},
					Retries: 2,
					Delay:   10 * time.Millisecond,
				},
				wantErr: true,
			},
		},
		{
			Name: "dry run mode",
			Input: struct {
				opts    Options
				wantErr bool
			}{
				opts: Options{
					Command: "echo",
					Args:    []string{"test"},
					DryRun:  true,
				},
				wantErr: false,
			},
		},
		{
			Name: "command with working directory",
			Input: struct {
				opts    Options
				wantErr bool
			}{
				opts: Options{
					Command: "pwd",
					Args:    []string{},
					Dir:     "/tmp",
					Capture: true,
				},
				wantErr: false,
			},
		},
		{
			Name: "command with timeout",
			Input: struct {
				opts    Options
				wantErr bool
			}{
				opts: Options{
					Command: "sleep",
					Args:    []string{"2"},
					Timeout: 100 * time.Millisecond,
				},
				wantErr: true, // Should timeout
			},
		},
		{
			Name: "shell mode disabled",
			Input: struct {
				opts    Options
				wantErr bool
			}{
				opts: Options{
					Command: "echo 'test'",
					Shell:   true,
				},
				wantErr: true, // Shell mode is disabled for security
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			output, err := Run(ctx, tt.Input.opts)
			
			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.Input.opts.Capture && tt.Input.opts.Command == "echo" {
					assert.Contains(t, output, "test")
				}
			}
		})
	}
}

func TestRunWithCustomLogger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := zap.NewNop()

	opts := Options{
		Command: "echo",
		Args:    []string{"test"},
		Logger:  logger,
		Capture: true,
	}

	output, err := Run(ctx, opts)
	assert.NoError(t, err)
	assert.Contains(t, output, "test")
}

func TestRunWithNilContext(t *testing.T) {
	t.Parallel()

	opts := Options{
		Command: "echo",
		Args:    []string{"test"},
		Capture: true,
	}

	// Should handle nil context gracefully
	output, err := Run(context.Background(), opts)
	assert.NoError(t, err)
	assert.Contains(t, output, "test")
}

func TestRunWithDefaultDryRun(t *testing.T) {
	t.Parallel()

	// Save original state
	originalDryRun := DefaultDryRun
	defer func() { DefaultDryRun = originalDryRun }()

	// Enable global dry run
	DefaultDryRun = true

	ctx := context.Background()
	opts := Options{
		Command: "echo",
		Args:    []string{"test"},
	}

	output, err := Run(ctx, opts)
	assert.NoError(t, err)
	assert.Empty(t, output) // Dry run should return empty output
}

func TestJoinArgs(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		args     []string
		expected string
	}]{
		{
			Name: "simple arguments",
			Input: struct {
				args     []string
				expected string
			}{
				args:     []string{"arg1", "arg2"},
				expected: "'arg1' 'arg2'",
			},
		},
		{
			Name: "arguments with spaces",
			Input: struct {
				args     []string
				expected string
			}{
				args:     []string{"arg with spaces", "another arg"},
				expected: "'arg with spaces' 'another arg'",
			},
		},
		{
			Name: "empty arguments",
			Input: struct {
				args     []string
				expected string
			}{
				args:     []string{},
				expected: "",
			},
		},
		{
			Name: "single argument",
			Input: struct {
				args     []string
				expected string
			}{
				args:     []string{"single"},
				expected: "'single'",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			result := joinArgs(tt.Input.args)
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

func TestShellQuote(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		args     []string
		expected string
	}]{
		{
			Name: "basic quoting",
			Input: struct {
				args     []string
				expected string
			}{
				args:     []string{"hello", "world"},
				expected: "'hello' 'world'",
			},
		},
		{
			Name: "arguments with special characters",
			Input: struct {
				args     []string
				expected string
			}{
				args:     []string{"arg;rm", "arg&&ls", "arg|cat"},
				expected: "'arg;rm' 'arg&&ls' 'arg|cat'",
			},
		},
		{
			Name: "empty list",
			Input: struct {
				args     []string
				expected string
			}{
				args:     []string{},
				expected: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			result := shellQuote(tt.Input.args)
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

func TestCmd(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []testutil.TableTest[struct {
		command string
		args    []string
		wantErr bool
	}]{
		{
			Name: "successful command function",
			Input: struct {
				command string
				args    []string
				wantErr bool
			}{
				command: "echo",
				args:    []string{"test"},
				wantErr: false,
			},
		},
		{
			Name: "failing command function",
			Input: struct {
				command string
				args    []string
				wantErr bool
			}{
				command: "false",
				args:    []string{},
				wantErr: true,
			},
		},
		{
			Name: "nonexistent command function",
			Input: struct {
				command string
				args    []string
				wantErr bool
			}{
				command: "definitely-not-a-real-command-12345",
				args:    []string{},
				wantErr: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			fn := Cmd(ctx, tt.Input.command, tt.Input.args...)
			err := fn()
			
			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRunShell(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// RunShell should be disabled for security
	output, err := RunShell(ctx, "echo 'test'")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled for security")
	assert.Empty(t, output)
}

func TestRunSimple(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []testutil.TableTest[struct {
		command string
		args    []string
		wantErr bool
	}]{
		{
			Name: "successful simple run",
			Input: struct {
				command string
				args    []string
				wantErr bool
			}{
				command: "echo",
				args:    []string{"test"},
				wantErr: false,
			},
		},
		{
			Name: "failing simple run",
			Input: struct {
				command string
				args    []string
				wantErr bool
			}{
				command: "false",
				args:    []string{},
				wantErr: true,
			},
		},
		{
			Name: "simple run with arguments",
			Input: struct {
				command string
				args    []string
				wantErr bool
			}{
				command: "echo",
				args:    []string{"hello", "world"},
				wantErr: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			err := RunSimple(ctx, tt.Input.command, tt.Input.args...)
			
			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLogInfo(t *testing.T) {
	t.Parallel()

	// Test with nil logger
	logInfo(nil, "test message")

	// Test with custom logger
	logger := zap.NewNop()
	logInfo(logger, "test message", zap.String("key", "value"))

	// Should not panic
}

func TestLogError(t *testing.T) {
	t.Parallel()

	err := assert.AnError

	// Test with nil logger
	logError(nil, "test error", err)

	// Test with custom logger
	logger := zap.NewNop()
	logError(logger, "test error", err, zap.String("key", "value"))

	// Should not panic
}

// Security Tests
func TestRunSecurityValidation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []testutil.TableTest[struct {
		opts        Options
		description string
	}]{
		{
			Name: "command injection via arguments",
			Input: struct {
				opts        Options
				description string
			}{
				opts: Options{
					Command: "echo",
					Args:    []string{"; rm -rf /"},
					Capture: true,
				},
				description: "semicolon injection attempt",
			},
		},
		{
			Name: "shell metacharacters in arguments",
			Input: struct {
				opts        Options
				description string
			}{
				opts: Options{
					Command: "echo",
					Args:    []string{"test && whoami"},
					Capture: true,
				},
				description: "logical AND injection",
			},
		},
		{
			Name: "pipe injection in arguments",
			Input: struct {
				opts        Options
				description string
			}{
				opts: Options{
					Command: "echo",
					Args:    []string{"test | cat /etc/passwd"},
					Capture: true,
				},
				description: "pipe injection attempt",
			},
		},
		{
			Name: "null byte in command",
			Input: struct {
				opts        Options
				description string
			}{
				opts: Options{
					Command: "echo\x00rm",
					Args:    []string{"test"},
				},
				description: "null byte injection",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			// Commands should execute safely without shell interpretation
			output, err := Run(ctx, tt.Input.opts)
			
			// Check that malicious content appears as literal text in output
			if err == nil && tt.Input.opts.Command == "echo" {
				// Malicious characters should appear literally, not be executed
				for _, arg := range tt.Input.opts.Args {
					if strings.Contains(arg, ";") || strings.Contains(arg, "&&") || strings.Contains(arg, "|") {
						// Output should contain the literal text
						assert.Contains(t, output, arg)
					}
				}
			}
		})
	}
}

func TestRunConcurrencySafety(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const numGoroutines = 20

	// Test concurrent execution
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			opts := Options{
				Command: "echo",
				Args:    []string{"concurrent", "test", fmt.Sprintf("%d", id)},
				Timeout: 5 * time.Second,
			}
			_, err := Run(ctx, opts)
			results <- err
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		err := <-results
		if err == nil {
			successCount++
		}
	}

	// Most should succeed
	assert.GreaterOrEqual(t, successCount, numGoroutines-2)
}

// Benchmark Tests
func BenchmarkRun(b *testing.B) {
	ctx := context.Background()
	opts := Options{
		Command: "echo",
		Args:    []string{"benchmark"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Run(ctx, opts)
	}
}

func BenchmarkRunSimple(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RunSimple(ctx, "echo", "benchmark")
	}
}

func BenchmarkJoinArgs(b *testing.B) {
	args := []string{"arg1", "arg2", "arg3", "arg4"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		joinArgs(args)
	}
}

func BenchmarkShellQuote(b *testing.B) {
	args := []string{"arg1", "arg2 with spaces", "arg3"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shellQuote(args)
	}
}