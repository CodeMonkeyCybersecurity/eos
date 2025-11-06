package eos_err

import (
	"errors"
	"testing"
)

func TestErrFallbackUsed(t *testing.T) {
	t.Parallel()
	if ErrFallbackUsed == nil {
		t.Fatal("ErrFallbackUsed should not be nil")
	}

	if ErrFallbackUsed.Error() != "fallback logger used" {
		t.Errorf("Expected 'fallback logger used', got '%s'", ErrFallbackUsed.Error())
	}
}

func TestErrReexecCompleted(t *testing.T) {
	t.Parallel()
	if ErrReexecCompleted == nil {
		t.Fatal("ErrReexecCompleted should not be nil")
	}

	if ErrReexecCompleted.Error() != "eos reexec completed" {
		t.Errorf("Expected 'eos reexec completed', got '%s'", ErrReexecCompleted.Error())
	}
}

func TestErrSecretNotFound(t *testing.T) {
	t.Parallel()
	if ErrSecretNotFound == nil {
		t.Fatal("ErrSecretNotFound should not be nil")
	}

	if ErrSecretNotFound.Error() != "vault secret not found" {
		t.Errorf("Expected 'vault secret not found', got '%s'", ErrSecretNotFound.Error())
	}
}

func TestUserError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		cause       error
		wantMessage string
	}{
		{
			name:        "simple error",
			cause:       errors.New("user mistake"),
			wantMessage: "user mistake",
		},
		{
			name:        "wrapped error",
			cause:       errors.New("config not found"),
			wantMessage: "config not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userErr := &UserError{cause: tt.cause}

			// Test Error() method
			if tt.cause == nil {
				// Skip error string test for nil cause as it will panic
			} else {
				got := userErr.Error()
				if got != tt.wantMessage {
					t.Errorf("Expected '%s', got '%s'", tt.wantMessage, got)
				}
			}

			// Test Unwrap() method
			unwrapped := userErr.Unwrap()
			if unwrapped != tt.cause {
				t.Errorf("Unwrap() returned different error than cause")
			}

			// Verify it implements error interface
			var _ error = userErr
		})
	}
}

func TestUserError_ErrorChaining(t *testing.T) {
	t.Parallel()
	baseErr := errors.New("base error")
	userErr := &UserError{cause: baseErr}

	// Test that errors.Is works correctly
	if !errors.Is(userErr, baseErr) {
		t.Error("errors.Is should recognize the wrapped error")
	}

	// Test that errors.Unwrap works
	if errors.Unwrap(userErr) != baseErr {
		t.Error("errors.Unwrap should return the base error")
	}
}
