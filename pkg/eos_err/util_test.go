package eos_err

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSetDebugMode(t *testing.T) {
	t.Parallel()
	// Save original state
	originalDebug := debugMode
	defer func() { debugMode = originalDebug }()

	// Test enabling debug mode
	SetDebugMode(true)
	if !DebugEnabled() {
		t.Error("Debug mode should be enabled")
	}

	// Test disabling debug mode
	SetDebugMode(false)
	if DebugEnabled() {
		t.Error("Debug mode should be disabled")
	}
}

func TestExtractSummary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name          string
		output        string
		maxCandidates int
		want          string
	}{
		{
			name:          "empty output",
			output:        "",
			maxCandidates: 3,
			want:          "No output provided.",
		},
		{
			name:          "whitespace only",
			output:        "   \n\n   ",
			maxCandidates: 3,
			want:          "No output provided.",
		},
		{
			name:          "single error line",
			output:        "Error: connection refused",
			maxCandidates: 3,
			want:          "Error: connection refused",
		},
		{
			name:          "multiple error lines",
			output:        "Info: starting\nError: connection failed\nFailed to connect\nPanic: unexpected state",
			maxCandidates: 2,
			want:          "Error: connection failed - Failed to connect",
		},
		{
			name:          "timeout error",
			output:        "Operation started\nTimeout: operation took too long\nCleanup complete",
			maxCandidates: 3,
			want:          "Timeout: operation took too long",
		},
		{
			name:          "fatal error",
			output:        "Starting process\nFatal: cannot allocate memory\nExiting",
			maxCandidates: 3,
			want:          "Fatal: cannot allocate memory",
		},
		{
			name:          "cannot error",
			output:        "Checking permissions\nCannot access file: permission denied",
			maxCandidates: 3,
			want:          "Cannot access file: permission denied",
		},
		{
			name:          "no error keywords",
			output:        "Operation successful\nAll tests passed\nComplete",
			maxCandidates: 3,
			want:          "Operation successful",
		},
		{
			name:          "mixed case errors",
			output:        "ERROR: database locked\nerror: invalid input\nError: file not found",
			maxCandidates: 3,
			want:          "ERROR: database locked - error: invalid input - Error: file not found",
		},
		{
			name:          "exceeding max candidates",
			output:        "Error 1\nError 2\nError 3\nError 4\nError 5",
			maxCandidates: 3,
			want:          "Error 1 - Error 2 - Error 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
			got := ExtractSummary(ctx, tt.output, tt.maxCandidates)
			if got != tt.want {
				t.Errorf("ExtractSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewExpectedError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Test with nil error
	if err := NewExpectedError(ctx, nil); err != nil {
		t.Error("NewExpectedError(nil) should return nil")
	}

	// Test with actual error
	originalErr := errors.New("user configuration error")
	wrappedErr := NewExpectedError(ctx, originalErr)

	if wrappedErr == nil {
		t.Fatal("NewExpectedError should not return nil for non-nil error")
	}

	// Verify it's a UserError
	var userErr *UserError
	if !errors.As(wrappedErr, &userErr) {
		t.Error("NewExpectedError should return a UserError")
	}

	// Verify the cause is preserved
	if !errors.Is(wrappedErr, originalErr) {
		t.Error("Wrapped error should preserve the original error")
	}
}

func TestIsExpectedUserError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "regular error",
			err:  errors.New("system error"),
			want: false,
		},
		{
			name: "user error",
			err:  &UserError{cause: errors.New("user mistake")},
			want: true,
		},
		{
			name: "wrapped user error",
			err:  NewExpectedError(context.Background(), errors.New("config error")),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
			if got := IsExpectedUserError(tt.err); got != tt.want {
				t.Errorf("IsExpectedUserError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractSummary_EdgeCases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Test with very long lines
	longLine := strings.Repeat("x", 1000) + " error: " + strings.Repeat("y", 1000)
	summary := ExtractSummary(ctx, longLine, 1)
	if !strings.Contains(summary, "error:") {
		t.Error("Should extract long lines with error keywords")
	}

	// Test with only newlines
	summary = ExtractSummary(ctx, "\n\n\n\n", 1)
	if summary != "No output provided." {
		t.Errorf("Expected 'No output provided.', got %q", summary)
	}

	// Test with unicode
	summary = ExtractSummary(ctx, "错误: 连接失败\nError: connection failed", 2)
	if !strings.Contains(summary, "Error: connection failed") {
		t.Error("Should handle unicode and extract error lines")
	}

	// Test fallback to first non-empty line when no error keywords found
	summary = ExtractSummary(ctx, "\n\nOperation completed successfully\nAll good\n", 3)
	if summary != "Operation completed successfully" {
		t.Errorf("Expected 'Operation completed successfully', got %q", summary)
	}

	// Test with maxCandidates = 0 (should truncate error candidates to empty slice)
	summary = ExtractSummary(ctx, "Error: test\nFailed: test", 0)
	if summary != "" { // Empty slice joined becomes empty string
		t.Errorf("Expected empty string for maxCandidates=0, got %q", summary)
	}
}
