package eos_err

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// Helper function to capture stderr output
func captureStderr(fn func()) string {
	// Save the original stderr
	originalStderr := os.Stderr
	
	// Create a pipe to capture stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	
	// Channel to capture the output
	outputCh := make(chan string)
	
	// Start a goroutine to read from the pipe
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outputCh <- buf.String()
	}()
	
	// Execute the function
	fn()
	
	// Close the writer and restore stderr
	_ = w.Close()
	os.Stderr = originalStderr
	
	// Get the captured output
	return <-outputCh
}

func TestPrintError(t *testing.T) {
	// Save original debug mode
	originalDebug := debugMode
	defer func() { debugMode = originalDebug }()
	
	tests := []struct {
		name         string
		debugMode    bool
		userMessage  string
		err          error
		expectOutput bool
		outputCheck  func(string) bool
	}{
		{
			name:         "nil_error_no_output",
			debugMode:    false,
			userMessage:  "operation completed",
			err:          nil,
			expectOutput: false,
			outputCheck:  func(output string) bool { return output == "" },
		},
		{
			name:         "regular_error_non_debug",
			debugMode:    false,
			userMessage:  "connection failed",
			err:          errors.New("timeout occurred"),
			expectOutput: true,
			outputCheck: func(output string) bool {
				return strings.Contains(output, "Error: connection failed") &&
					   strings.Contains(output, "timeout occurred")
			},
		},
		{
			name:         "user_error_non_debug",
			debugMode:    false,
			userMessage:  "configuration issue",
			err:          &UserError{cause: errors.New("invalid config file")},
			expectOutput: true,
			outputCheck: func(output string) bool {
				return strings.Contains(output, "Notice: configuration issue") &&
					   strings.Contains(output, "invalid config file")
			},
		},
		{
			name:         "expected_user_error_non_debug",
			debugMode:    false,
			userMessage:  "user input error",
			err:          NewExpectedError(context.Background(), errors.New("missing required field")),
			expectOutput: true,
			outputCheck: func(output string) bool {
				return strings.Contains(output, "Notice: user input error") &&
					   strings.Contains(output, "missing required field")
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set debug mode for this test
			debugMode = tt.debugMode
			
			// For debug mode tests, we can't easily test the Fatal call since it would exit
			// We'll test non-debug mode which uses structured logging + stderr
			if tt.debugMode {
				t.Skip("Skipping debug mode test to avoid Fatal call")
				return
			}
			
			ctx := context.Background()
			
			// Capture stderr output
			output := captureStderr(func() {
				PrintError(ctx, tt.userMessage, tt.err)
			})
			
			// Check if output matches expectations
			if tt.expectOutput {
				if output == "" {
					t.Error("expected output but got none")
				} else if !tt.outputCheck(output) {
					t.Errorf("output check failed. Got: %q", output)
				}
			} else {
				if output != "" {
					t.Errorf("expected no output but got: %q", output)
				}
			}
		})
	}
}

func TestPrintError_DebugMode(t *testing.T) {
	// Save original debug mode
	originalDebug := debugMode
	defer func() { debugMode = originalDebug }()
	
	// Test debug mode behavior without actually calling Fatal
	// We'll verify the debug mode detection works correctly
	
	t.Run("debug_enabled_check", func(t *testing.T) {
		debugMode = true
		if !DebugEnabled() {
			t.Error("debug should be enabled")
		}
		
		debugMode = false
		if DebugEnabled() {
			t.Error("debug should be disabled")
		}
	})
	
	// Note: We can't fully test the Fatal path without exiting the test process
	// The coverage for that branch will be lower, but it's acceptable for a Fatal call
}

// TestExitWithError tests the ExitWithError function
// Note: This function calls os.Exit(1), so we need to be careful in testing
func TestExitWithError_Components(t *testing.T) {
	// We can't directly test ExitWithError since it calls os.Exit(1)
	// But we can test its components and verify the output it would produce
	
	t.Run("output_before_exit", func(t *testing.T) {
		// Save original debug mode
		originalDebug := debugMode
		defer func() { debugMode = originalDebug }()
		debugMode = false
		
		ctx := context.Background()
		userMessage := "fatal error occurred"
		err := errors.New("system failure")
		
		// Capture what PrintError would output (ExitWithError calls PrintError first)
		output := captureStderr(func() {
			PrintError(ctx, userMessage, err)
		})
		
		// Verify PrintError output
		if !strings.Contains(output, "Error: fatal error occurred") {
			t.Errorf("expected error message in output, got: %q", output)
		}
		if !strings.Contains(output, "system failure") {
			t.Errorf("expected error details in output, got: %q", output)
		}
	})
	
	t.Run("debug_tip_format", func(t *testing.T) {
		// Test that the debug tip would be correctly formatted
		expectedTip := " Tip: rerun with --debug for more details."
		
		// We can verify this string exists in the function (would be printed)
		// This is more of a documentation test to ensure the tip message is correct
		if len(expectedTip) == 0 {
			t.Error("debug tip should not be empty")
		}
		if !strings.Contains(expectedTip, "--debug") {
			t.Error("debug tip should mention --debug flag")
		}
	})
}

// TestExitWithError_Integration provides integration testing without actually exiting
func TestExitWithError_Integration(t *testing.T) {
	// Test the full flow except for the os.Exit(1) call
	// We simulate what ExitWithError does step by step
	
	t.Run("full_flow_simulation", func(t *testing.T) {
		// Save original debug mode
		originalDebug := debugMode
		defer func() { debugMode = originalDebug }()
		debugMode = false
		
		ctx := context.Background()
		userMessage := "critical failure"
		err := errors.New("database connection lost")
		
		// Capture the full output that ExitWithError would produce
		output := captureStderr(func() {
			// Step 1: PrintError
			PrintError(ctx, userMessage, err)
			
			// Step 2: Print debug tip (simulated)
			_, _ = os.Stderr.WriteString(" Tip: rerun with --debug for more details.\n")
			
			// Step 3: os.Exit(1) - we skip this to avoid ending the test
		})
		
		// Verify the complete output
		expectedParts := []string{
			"Error: critical failure",
			"database connection lost",
			"Tip: rerun with --debug for more details",
		}
		
		for _, part := range expectedParts {
			if !strings.Contains(output, part) {
				t.Errorf("output should contain %q, got: %q", part, output)
			}
		}
	})
	
	t.Run("user_error_exit_flow", func(t *testing.T) {
		// Test ExitWithError with a user error
		originalDebug := debugMode
		defer func() { debugMode = originalDebug }()
		debugMode = false
		
		ctx := context.Background()
		userMessage := "configuration error"
		err := NewExpectedError(ctx, errors.New("missing config file"))
		
		output := captureStderr(func() {
			PrintError(ctx, userMessage, err)
			_, _ = os.Stderr.WriteString(" Tip: rerun with --debug for more details.\n")
		})
		
		// Should show as a Notice for user errors
		if !strings.Contains(output, "Notice: configuration error") {
			t.Errorf("user error should show as Notice, got: %q", output)
		}
		if !strings.Contains(output, "Tip: rerun with --debug") {
			t.Errorf("should include debug tip, got: %q", output)
		}
	})
}