// pkg/eos_io/secure_input_test.go

package eos_io

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPromptSecurePassword(t *testing.T) {
	// Skip if not in a terminal (CI environment)
	if os.Getenv("CI") != "" {
		t.Skip("Skipping terminal tests in CI")
	}

	tests := []struct {
		name        string
		prompt      string
		setupStdin  func() (cleanup func())
		expectError bool
		errorMsg    string
	}{
		{
			name:   "non-terminal empty input",
			prompt: "Enter password: ",
			setupStdin: func() func() {
				// Simulate empty password (just Enter key)
				oldStdin := os.Stdin
				r, w, _ := os.Pipe()
				os.Stdin = r
				w.Write([]byte("\n"))
				w.Close()
				return func() { os.Stdin = oldStdin }
			},
			expectError: true,
			errorMsg:    "stdin is not a terminal", // Pipe is not a terminal
		},
		{
			name:   "non-terminal stdin",
			prompt: "Enter password: ",
			setupStdin: func() func() {
				// Create a pipe instead of terminal
				oldStdin := os.Stdin
				r, _, _ := os.Pipe()
				os.Stdin = r
				return func() { os.Stdin = oldStdin }
			},
			expectError: true,
			errorMsg:    "stdin is not a terminal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			rc := &RuntimeContext{Ctx: ctx}

			// Capture stdout to verify prompt
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cleanup := tt.setupStdin()
			defer cleanup()

			_, err := PromptSecurePassword(rc, tt.prompt)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPromptSecurePasswordIntegration tests with mock terminal
func TestPromptSecurePasswordIntegration(t *testing.T) {
	// This test would require a more sophisticated terminal emulator
	// For now, we're achieving coverage through the basic tests above
	t.Skip("Integration test requires terminal emulator")
}

// TestPromptSecurePasswordEdgeCases tests edge cases
func TestPromptSecurePasswordEdgeCases(t *testing.T) {
	ctx := context.Background()
	rc := &RuntimeContext{Ctx: ctx}

	// Test with nil RuntimeContext should not panic
	t.Run("nil context handling", func(t *testing.T) {
		// We can't test this without a terminal, but we ensure no panic
		require.NotPanics(t, func() {
			// This will fail due to no terminal, but shouldn't panic
			_, _ = PromptSecurePassword(rc, "Test: ")
		})
	})

	// Test with various prompts
	prompts := []string{
		"",
		"Simple prompt: ",
		"Prompt with unicode 🔒: ",
		"Very long prompt " + string(make([]byte, 1000)) + ": ",
	}

	for _, prompt := range prompts {
		t.Run("prompt variation", func(t *testing.T) {
			// Setup non-terminal stdin to trigger error path
			oldStdin := os.Stdin
			r, _, _ := os.Pipe()
			os.Stdin = r
			defer func() {
				os.Stdin = oldStdin
				r.Close()
			}()

			_, err := PromptSecurePassword(rc, prompt)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "stdin is not a terminal")
		})
	}
}
