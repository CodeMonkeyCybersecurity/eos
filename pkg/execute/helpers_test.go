package execute

import (
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestMax(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		a        int
		b        int
		expected int
	}]{
		{
			Name: "first argument larger",
			Input: struct {
				a        int
				b        int
				expected int
			}{
				a:        10,
				b:        5,
				expected: 10,
			},
		},
		{
			Name: "second argument larger",
			Input: struct {
				a        int
				b        int
				expected int
			}{
				a:        3,
				b:        7,
				expected: 7,
			},
		},
		{
			Name: "equal arguments",
			Input: struct {
				a        int
				b        int
				expected int
			}{
				a:        5,
				b:        5,
				expected: 5,
			},
		},
		{
			Name: "negative numbers",
			Input: struct {
				a        int
				b        int
				expected int
			}{
				a:        -3,
				b:        -7,
				expected: -3,
			},
		},
		{
			Name: "zero and positive",
			Input: struct {
				a        int
				b        int
				expected int
			}{
				a:        0,
				b:        1,
				expected: 1,
			},
		},
		{
			Name: "zero and negative",
			Input: struct {
				a        int
				b        int
				expected int
			}{
				a:        0,
				b:        -1,
				expected: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			result := max(tt.Input.a, tt.Input.b)
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

func TestDefaultTimeout(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		input    time.Duration
		expected time.Duration
	}]{
		{
			Name: "positive timeout",
			Input: struct {
				input    time.Duration
				expected time.Duration
			}{
				input:    5 * time.Second,
				expected: 5 * time.Second,
			},
		},
		{
			Name: "zero timeout",
			Input: struct {
				input    time.Duration
				expected time.Duration
			}{
				input:    0,
				expected: 30 * time.Second,
			},
		},
		{
			Name: "negative timeout",
			Input: struct {
				input    time.Duration
				expected time.Duration
			}{
				input:    -5 * time.Second,
				expected: 30 * time.Second,
			},
		},
		{
			Name: "very small positive timeout",
			Input: struct {
				input    time.Duration
				expected time.Duration
			}{
				input:    1 * time.Nanosecond,
				expected: 1 * time.Nanosecond,
			},
		},
		{
			Name: "very large timeout",
			Input: struct {
				input    time.Duration
				expected time.Duration
			}{
				input:    24 * time.Hour,
				expected: 24 * time.Hour,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			result := defaultTimeout(tt.Input.input)
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

func TestBuildCommandString(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		command  string
		args     []string
		expected string
	}]{
		{
			Name: "command with no args",
			Input: struct {
				command  string
				args     []string
				expected string
			}{
				command:  "echo",
				args:     []string{},
				expected: "echo ",
			},
		},
		{
			Name: "command with single arg",
			Input: struct {
				command  string
				args     []string
				expected string
			}{
				command:  "echo",
				args:     []string{"hello"},
				expected: "echo hello",
			},
		},
		{
			Name: "command with multiple args",
			Input: struct {
				command  string
				args     []string
				expected string
			}{
				command:  "ls",
				args:     []string{"-la", "/tmp"},
				expected: "ls -la /tmp",
			},
		},
		{
			Name: "command with args containing spaces",
			Input: struct {
				command  string
				args     []string
				expected string
			}{
				command:  "echo",
				args:     []string{"hello world", "test"},
				expected: "echo hello world test",
			},
		},
		{
			Name: "empty command with args",
			Input: struct {
				command  string
				args     []string
				expected string
			}{
				command:  "",
				args:     []string{"arg1", "arg2"},
				expected: " arg1 arg2",
			},
		},
		{
			Name: "command with empty args",
			Input: struct {
				command  string
				args     []string
				expected string
			}{
				command:  "test",
				args:     []string{"", "arg2"},
				expected: "test  arg2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			result := buildCommandString(tt.Input.command, tt.Input.args...)
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

// Security Tests for Helper Functions
func TestBuildCommandStringSecurity(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		command     string
		args        []string
		description string
	}]{
		{
			Name: "command injection in command",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo; rm -rf /",
				args:        []string{"test"},
				description: "semicolon injection in command",
			},
		},
		{
			Name: "shell metacharacters in args",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"test && whoami"},
				description: "logical AND in arguments",
			},
		},
		{
			Name: "pipe injection in args",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"safe | cat /etc/passwd"},
				description: "pipe injection in arguments",
			},
		},
		{
			Name: "null bytes in command and args",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo\x00malicious",
				args:        []string{"test\x00injection"},
				description: "null byte injection",
			},
		},
		{
			Name: "backtick command substitution",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"`whoami`"},
				description: "backtick command substitution",
			},
		},
		{
			Name: "dollar parentheses substitution",
			Input: struct {
				command     string
				args        []string
				description string
			}{
				command:     "echo",
				args:        []string{"$(id)"},
				description: "dollar parentheses substitution",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			
			// buildCommandString should concatenate safely without interpretation
			result := buildCommandString(tt.Input.command, tt.Input.args...)
			
			// Result should contain the literal strings
			assert.Contains(t, result, tt.Input.command)
			for _, arg := range tt.Input.args {
				assert.Contains(t, result, arg)
			}
			
			// Function should not execute or interpret the strings
			// It's just string concatenation
		})
	}
}

// Test Edge Cases
func TestHelpersEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("max with large numbers", func(t *testing.T) {
		t.Parallel()
		
		result := max(2147483647, 2147483646) // Max int32 values
		assert.Equal(t, 2147483647, result)
	})

	t.Run("defaultTimeout with duration edge cases", func(t *testing.T) {
		t.Parallel()
		
		// Test with maximum duration
		maxDuration := time.Duration(1<<63 - 1)
		result := defaultTimeout(maxDuration)
		assert.Equal(t, maxDuration, result)
		
		// Test with minimum duration
		minDuration := time.Duration(-1 << 63)
		result = defaultTimeout(minDuration)
		assert.Equal(t, 30*time.Second, result)
	})

	t.Run("buildCommandString with nil args slice", func(t *testing.T) {
		t.Parallel()
		
		result := buildCommandString("echo", nil...)
		assert.Equal(t, "echo ", result)
	})

	t.Run("buildCommandString with very long strings", func(t *testing.T) {
		t.Parallel()
		
		longCommand := string(make([]byte, 1000))
		longArg := string(make([]byte, 1000))
		
		result := buildCommandString(longCommand, longArg)
		assert.Contains(t, result, longCommand)
		assert.Contains(t, result, longArg)
	})
}

// Benchmark Tests
func BenchmarkMax(b *testing.B) {
	for i := 0; i < b.N; i++ {
		max(i, i+1)
	}
}

func BenchmarkDefaultTimeout(b *testing.B) {
	timeout := 5 * time.Second
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		defaultTimeout(timeout)
	}
}

func BenchmarkDefaultTimeoutZero(b *testing.B) {
	for i := 0; i < b.N; i++ {
		defaultTimeout(0)
	}
}

func BenchmarkBuildCommandString(b *testing.B) {
	args := []string{"arg1", "arg2", "arg3"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildCommandString("command", args...)
	}
}

func BenchmarkBuildCommandStringLarge(b *testing.B) {
	// Test with many arguments
	args := make([]string, 100)
	for i := range args {
		args[i] = "argument"
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildCommandString("command", args...)
	}
}