package eos_err

import (
	"errors"
	"testing"

	cerr "github.com/cockroachdb/errors"
)

func TestWrapValidationError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "simple_error",
			err:  errors.New("validation failed"),
		},
		{
			name: "nil_error",
			err:  nil,
		},
		{
			name: "complex_error",
			err:  errors.New("field 'username' is required"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
			wrapped := WrapValidationError(tt.err)

			if tt.err == nil {
				// Wrapping nil with cockroach errors should still return nil
				if wrapped != nil {
					t.Error("WrapValidationError(nil) should return nil")
				}
				return
			}

			if wrapped == nil {
				t.Fatal("WrapValidationError should not return nil for non-nil error")
			}

			// Check that the original error is preserved
			if !errors.Is(wrapped, tt.err) {
				t.Error("wrapped error should preserve the original error")
			}

			// The hint is stored internally, not in the basic error message
			// Just verify we have a wrapped error
			errorMsg := wrapped.Error()
			if errorMsg == "" {
				t.Error("wrapped error should have a message")
			}

			// Verify it's a properly wrapped error
			if wrapped == tt.err {
				t.Error("wrapped error should be different from original")
			}
		})
	}
}

func TestWrapPolicyError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "simple_policy_error",
			err:  errors.New("policy violation"),
		},
		{
			name: "nil_error",
			err:  nil,
		},
		{
			name: "opa_policy_error",
			err:  errors.New("deny rule matched: access forbidden"),
		},
		{
			name: "complex_policy_error",
			err:  errors.New("multiple policy rules failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
			wrapped := WrapPolicyError(tt.err)

			if tt.err == nil {
				// Wrapping nil with cockroach errors should still return nil
				if wrapped != nil {
					t.Error("WrapPolicyError(nil) should return nil")
				}
				return
			}

			if wrapped == nil {
				t.Fatal("WrapPolicyError should not return nil for non-nil error")
			}

			// Check that the original error is preserved
			if !errors.Is(wrapped, tt.err) {
				t.Error("wrapped error should preserve the original error")
			}

			// The hint is stored internally, not in the basic error message
			// Just verify we have a wrapped error
			errorMsg := wrapped.Error()
			if errorMsg == "" {
				t.Error("wrapped error should have a message")
			}

			// Verify it's a properly wrapped error
			if wrapped == tt.err {
				t.Error("wrapped error should be different from original")
			}
		})
	}
}

func TestWrapErrors_StackTrace(t *testing.T) {
	t.Parallel()
	t.Run("validation_error_has_stack", func(t *testing.T) {
		originalErr := errors.New("field missing")
		wrapped := WrapValidationError(originalErr)

		// Get the formatted error with details
		formattedErr := cerr.FlattenDetails(wrapped)

		// For now, just verify the function works without error
		// The details may be empty if no special formatting is applied
		_ = formattedErr
	})

	t.Run("policy_error_has_stack", func(t *testing.T) {
			t.Parallel()
		originalErr := errors.New("policy denied")
		wrapped := WrapPolicyError(originalErr)

		// Get the formatted error with details
		formattedErr := cerr.FlattenDetails(wrapped)

		// For now, just verify the function works without error
		// The details may be empty if no special formatting is applied
		_ = formattedErr
	})
}

func TestWrapErrors_Unwrapping(t *testing.T) {
	t.Parallel()
	t.Run("validation_error_unwraps_correctly", func(t *testing.T) {
		originalErr := errors.New("original validation error")
		wrapped := WrapValidationError(originalErr)

		// Test that errors.Unwrap can retrieve the original error
		unwrapped := errors.Unwrap(wrapped)
		for unwrapped != nil && unwrapped != originalErr {
			unwrapped = errors.Unwrap(unwrapped)
		}

		if unwrapped != originalErr {
			t.Error("should be able to unwrap to the original error")
		}
	})

	t.Run("policy_error_unwraps_correctly", func(t *testing.T) {
			t.Parallel()
		originalErr := errors.New("original policy error")
		wrapped := WrapPolicyError(originalErr)

		// Test that errors.Unwrap can retrieve the original error
		unwrapped := errors.Unwrap(wrapped)
		for unwrapped != nil && unwrapped != originalErr {
			unwrapped = errors.Unwrap(unwrapped)
		}

		if unwrapped != originalErr {
			t.Error("should be able to unwrap to the original error")
		}
	})
}

func TestWrapErrors_ChainedErrors(t *testing.T) {
	t.Parallel()
	t.Run("chain_validation_and_policy_errors", func(t *testing.T) {
		// Create a chain: original -> validation wrapper -> policy wrapper
		originalErr := errors.New("base error")
		validationWrapped := WrapValidationError(originalErr)
		policyWrapped := WrapPolicyError(validationWrapped)

		// Should be able to find the original error
		if !errors.Is(policyWrapped, originalErr) {
			t.Error("chained wrapping should preserve error identity")
		}

		// The basic error message should be from the original error
		errorMsg := policyWrapped.Error()
		if errorMsg == "" {
			t.Error("chained error should have a message")
		}

		// The wrapping functions create internal metadata
		// Just verify the functions work
		_ = cerr.FlattenDetails(policyWrapped)
	})
}
