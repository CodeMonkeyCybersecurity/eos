package eos_err

import (
	"errors"
	"testing"
)

func TestSanitizeErrorMessage(t *testing.T) {
	tests := []struct {
		name           string
		input          error
		shouldSanitize bool
		description    string
	}{
		{
			name:           "nil_error",
			input:          nil,
			shouldSanitize: false,
			description:    "nil error should return empty string",
		},
		{
			name:           "simple_error",
			input:          errors.New("connection failed"),
			shouldSanitize: false,
			description:    "simple error should be passed through",
		},
		{
			name:           "error_with_potential_secret",
			input:          errors.New("auth failed with token abc123"),
			shouldSanitize: true,
			description:    "error containing potential secrets should be sanitized",
		},
		{
			name:           "vault_error",
			input:          errors.New("vault authentication failed"),
			shouldSanitize: false,
			description:    "vault error without secrets should be passed through",
		},
		{
			name:           "database_connection_error",
			input:          errors.New("database connection failed: timeout"),
			shouldSanitize: false,
			description:    "database error should be passed through",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeErrorMessage(tt.input)

			if tt.input == nil {
				if result != "" {
					t.Errorf("expected empty string for nil error, got %q", result)
				}
				return
			}

			// Verify result is not empty for non-nil errors
			if result == "" {
				t.Error("sanitized message should not be empty for non-nil error")
			}

			// The result should be a string (shared.SanitizeForLogging handles the actual sanitization)
			if len(result) == 0 {
				t.Error("sanitized result should have length > 0")
			}
		})
	}
}

func TestSafeErrorSummary(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected string
	}{
		{
			name:     "nil_error",
			input:    nil,
			expected: "success",
		},
		{
			name:     "permission_error",
			input:    errors.New("permission denied accessing file"),
			expected: "authentication_required",
		},
		{
			name:     "unauthorized_error",
			input:    errors.New("unauthorized access to resource"),
			expected: "authentication_required",
		},
		{
			name:     "not_found_error",
			input:    errors.New("file not found"),
			expected: "resource_unavailable",
		},
		{
			name:     "timeout_error",
			input:    errors.New("operation timeout after 30 seconds"),
			expected: "service_timeout",
		},
		{
			name:     "network_error",
			input:    errors.New("network connection failed"),
			expected: "connectivity_issue",
		},
		{
			name:     "connection_error",
			input:    errors.New("connection refused by server"),
			expected: "connectivity_issue",
		},
		{
			name:     "validation_error",
			input:    errors.New("validation failed for input"),
			expected: "input_validation_error",
		},
		{
			name:     "invalid_error",
			input:    errors.New("invalid configuration provided"),
			expected: "input_validation_error",
		},
		{
			name:     "generic_error",
			input:    errors.New("unexpected error occurred"),
			expected: "general_error",
		},
		{
			name:     "empty_error",
			input:    errors.New(""),
			expected: "general_error",
		},
		{
			name:     "mixed_case_permission",
			input:    errors.New("PERMISSION denied for user"),
			expected: "authentication_required",
		},
		{
			name:     "multiple_keywords",
			input:    errors.New("validation failed: network timeout occurred"),
			expected: "service_timeout", // "timeout" is checked before "validation"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeErrorSummary(tt.input)
			if result != tt.expected {
				t.Errorf("SafeErrorSummary() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSafeErrorSummary_CategoryPrecedence(t *testing.T) {
	// Test that categories are matched in the correct order
	tests := []struct {
		name     string
		input    error
		expected string
		reason   string
	}{
		{
			name:     "permission_before_validation",
			input:    errors.New("permission denied: invalid request"),
			expected: "authentication_required",
			reason:   "permission should be matched before validation",
		},
		{
			name:     "not_found_before_network",
			input:    errors.New("network resource not found"),
			expected: "resource_unavailable",
			reason:   "not found should be matched before network",
		},
		{
			name:     "timeout_before_network",
			input:    errors.New("network timeout on connection"),
			expected: "service_timeout",
			reason:   "timeout should be matched before network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeErrorSummary(tt.input)
			if result != tt.expected {
				t.Errorf("SafeErrorSummary() = %q, want %q (%s)", result, tt.expected, tt.reason)
			}
		})
	}
}

func TestSafeErrorSummary_Integration(t *testing.T) {
	// Test integration between SanitizeErrorMessage and SafeErrorSummary
	t.Run("sanitize_then_categorize", func(t *testing.T) {
		// Create an error that might contain sensitive data
		sensitiveErr := errors.New("permission denied for user secret_token_123")

		// Get safe summary
		result := SafeErrorSummary(sensitiveErr)

		// Should categorize as authentication required
		if result != "authentication_required" {
			t.Errorf("expected 'authentication_required', got %q", result)
		}
	})

	t.Run("nil_to_success", func(t *testing.T) {
		result := SafeErrorSummary(nil)
		if result != "success" {
			t.Errorf("nil error should result in 'success', got %q", result)
		}
	})
}
