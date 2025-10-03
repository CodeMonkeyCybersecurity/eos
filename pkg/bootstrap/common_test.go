package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// TestClassifyError_Permanent tests that permanent errors are correctly identified
func TestClassifyError_Permanent(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorClass
	}{
		// Validation errors
		{
			name:     "validation failed",
			err:      errors.New("validation failed: invalid configuration"),
			expected: ErrorPermanent,
		},
		{
			name:     "config validation error",
			err:      errors.New("config validation error: missing required field"),
			expected: ErrorPermanent,
		},

		// File/resource not found
		{
			name:     "file not found",
			err:      errors.New("file not found: /etc/config.yaml"),
			expected: ErrorPermanent,
		},
		{
			name:     "service not found",
			err:      errors.New("service not found: consul"),
			expected: ErrorPermanent,
		},
		{
			name:     "no such file",
			err:      errors.New("no such file or directory"),
			expected: ErrorPermanent,
		},

		// Permission errors
		{
			name:     "permission denied",
			err:      errors.New("permission denied"),
			expected: ErrorPermanent,
		},
		{
			name:     "access denied",
			err:      errors.New("access denied to resource"),
			expected: ErrorPermanent,
		},

		// Port/binding errors
		{
			name:     "address already in use",
			err:      errors.New("bind: address already in use"),
			expected: ErrorPermanent,
		},

		// Consul multi-interface error (real error from logs)
		{
			name:     "multiple private IPv4 addresses",
			err:      errors.New("Config validation failed: Multiple private IPv4 addresses found. Please configure one with 'bind' and/or 'advertise'."),
			expected: ErrorPermanent,
		},

		// Masked service
		{
			name:     "masked service",
			err:      errors.New("service is masked and cannot be started"),
			expected: ErrorPermanent,
		},

		// Command not found
		{
			name:     "command not found",
			err:      errors.New("command not found: consul"),
			expected: ErrorPermanent,
		},

		// Invalid configuration
		{
			name:     "invalid argument",
			err:      errors.New("invalid argument provided"),
			expected: ErrorPermanent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			if result != tt.expected {
				t.Errorf("ClassifyError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// TestClassifyError_Transient tests that transient errors are correctly identified
func TestClassifyError_Transient(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorClass
	}{
		// Timeout errors
		{
			name:     "timeout",
			err:      errors.New("operation timeout exceeded"),
			expected: ErrorTransient,
		},
		{
			name:     "timed out",
			err:      errors.New("connection timed out"),
			expected: ErrorTransient,
		},
		{
			name:     "i/o timeout",
			err:      errors.New("i/o timeout reading response"),
			expected: ErrorTransient,
		},
		{
			name:     "deadline exceeded",
			err:      errors.New("context deadline exceeded"),
			expected: ErrorTransient,
		},

		// Connection errors
		{
			name:     "connection refused",
			err:      errors.New("dial tcp: connection refused"),
			expected: ErrorTransient,
		},
		{
			name:     "connection reset",
			err:      errors.New("connection reset by peer"),
			expected: ErrorTransient,
		},
		{
			name:     "network unreachable",
			err:      errors.New("network unreachable"),
			expected: ErrorTransient,
		},

		// Temporary failures
		{
			name:     "temporary failure",
			err:      errors.New("temporary failure in name resolution"),
			expected: ErrorTransient,
		},
		{
			name:     "resource temporarily unavailable",
			err:      errors.New("resource temporarily unavailable"),
			expected: ErrorTransient,
		},

		// Service unavailable
		{
			name:     "service unavailable",
			err:      errors.New("503 service unavailable"),
			expected: ErrorTransient,
		},

		// Lock/busy errors
		{
			name:     "lock error",
			err:      errors.New("failed to acquire lock"),
			expected: ErrorTransient,
		},
		{
			name:     "busy",
			err:      errors.New("resource is busy"),
			expected: ErrorTransient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			if result != tt.expected {
				t.Errorf("ClassifyError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// TestClassifyError_Ambiguous tests that unknown errors are classified as ambiguous
func TestClassifyError_Ambiguous(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorClass
	}{
		{
			name:     "unknown error",
			err:      errors.New("something went wrong"),
			expected: ErrorAmbiguous,
		},
		{
			name:     "custom error",
			err:      errors.New("unexpected state encountered"),
			expected: ErrorAmbiguous,
		},
		{
			name:     "generic failure",
			err:      errors.New("operation failed"),
			expected: ErrorAmbiguous,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			if result != tt.expected {
				t.Errorf("ClassifyError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// TestClassifyError_Nil tests that nil errors are handled correctly
func TestClassifyError_Nil(t *testing.T) {
	result := ClassifyError(nil)
	if result != ErrorTransient {
		t.Errorf("ClassifyError(nil) = %v, want %v (nil means success)", result, ErrorTransient)
	}
}

// TestClassifyError_WrappedError tests that wrapped errors are properly unwrapped and classified
func TestClassifyError_WrappedError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorClass
	}{
		{
			name:     "wrapped validation error",
			err:      fmt.Errorf("failed to configure consul: %w", errors.New("validation failed")),
			expected: ErrorPermanent,
		},
		{
			name:     "deeply wrapped timeout",
			err:      fmt.Errorf("operation failed: %w", fmt.Errorf("network error: %w", errors.New("timeout"))),
			expected: ErrorTransient,
		},
		{
			name:     "wrapped not found",
			err:      fmt.Errorf("cannot start service: %w", errors.New("service not found")),
			expected: ErrorPermanent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			if result != tt.expected {
				t.Errorf("ClassifyError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// TestClassifyError_ConflictingPatterns tests precedence when error contains multiple patterns
func TestClassifyError_ConflictingPatterns(t *testing.T) {
	// Permanent patterns should take precedence over transient
	err := errors.New("timeout occurred during validation")
	result := ClassifyError(err)

	// Should be classified as Permanent because "validation" is checked first
	if result != ErrorPermanent {
		t.Errorf("ClassifyError(conflicting patterns) = %v, want %v (permanent should take precedence)", result, ErrorPermanent)
	}
}

// TestWithRetry_PermanentError_NoRetry tests that permanent errors fail fast without retry
func TestWithRetry_PermanentError_NoRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	config := RetryConfig{
		MaxAttempts:       5,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          1 * time.Second,
		BackoffMultiplier: 2.0,
	}

	attemptCount := 0
	operation := func() error {
		attemptCount++
		return errors.New("validation failed: invalid configuration")
	}

	startTime := time.Now()
	err := WithRetry(rc, config, operation)
	duration := time.Since(startTime)

	// Should fail immediately (< 200ms) with only 1 attempt
	if attemptCount != 1 {
		t.Errorf("Permanent error retry count = %d, want 1 (should not retry)", attemptCount)
	}

	if duration > 200*time.Millisecond {
		t.Errorf("Permanent error took %v, want < 200ms (should fail fast)", duration)
	}

	if err == nil {
		t.Error("WithRetry returned nil error, want permanent error")
	}

	if !strings.Contains(err.Error(), "permanent error") {
		t.Errorf("Error message = %v, want to contain 'permanent error'", err)
	}
}

// TestWithRetry_TransientError_Retries tests that transient errors are retried with backoff
func TestWithRetry_TransientError_Retries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	config := RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      50 * time.Millisecond,
		MaxDelay:          1 * time.Second,
		BackoffMultiplier: 2.0,
	}

	attemptCount := 0
	operation := func() error {
		attemptCount++
		if attemptCount < 3 {
			return errors.New("connection timeout")
		}
		return nil // Succeed on third attempt
	}

	err := WithRetry(rc, config, operation)

	// Should retry and eventually succeed
	if err != nil {
		t.Errorf("WithRetry returned error %v, want nil (should succeed after retries)", err)
	}

	if attemptCount != 3 {
		t.Errorf("Transient error retry count = %d, want 3", attemptCount)
	}
}

// TestWithRetry_AmbiguousError_LimitedRetries tests that ambiguous errors retry max 2 times
func TestWithRetry_AmbiguousError_LimitedRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	config := RetryConfig{
		MaxAttempts:       5,
		InitialDelay:      50 * time.Millisecond,
		MaxDelay:          1 * time.Second,
		BackoffMultiplier: 2.0,
	}

	attemptCount := 0
	operation := func() error {
		attemptCount++
		return errors.New("unknown error occurred")
	}

	err := WithRetry(rc, config, operation)

	// Should retry only 2 times total for ambiguous errors
	if attemptCount != 2 {
		t.Errorf("Ambiguous error retry count = %d, want 2 (limited retries)", attemptCount)
	}

	if err == nil {
		t.Error("WithRetry returned nil error, want ambiguous error after 2 attempts")
	}

	if !strings.Contains(err.Error(), "ambiguous error") {
		t.Errorf("Error message = %v, want to contain 'ambiguous error'", err)
	}
}

// TestWithRetry_MaxAttemptsReached tests behavior when max attempts is reached
func TestWithRetry_MaxAttemptsReached(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	config := RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}

	attemptCount := 0
	operation := func() error {
		attemptCount++
		return errors.New("connection refused") // Transient error
	}

	err := WithRetry(rc, config, operation)

	if attemptCount != 3 {
		t.Errorf("Retry count = %d, want 3 (max attempts)", attemptCount)
	}

	if err == nil {
		t.Error("WithRetry returned nil error, want error after max attempts")
	}
}

// TestWithRetry_ContextCancellation tests that retry respects context cancellation
func TestWithRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	config := RetryConfig{
		MaxAttempts:       10,
		InitialDelay:      50 * time.Millisecond,
		MaxDelay:          1 * time.Second,
		BackoffMultiplier: 2.0,
	}

	attemptCount := 0
	operation := func() error {
		attemptCount++
		return errors.New("connection timeout") // Transient error
	}

	err := WithRetry(rc, config, operation)

	// Should be cancelled before reaching max attempts
	if err == nil {
		t.Error("WithRetry returned nil error, want context cancellation error")
	}

	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("Error message = %v, want to contain 'cancelled'", err)
	}

	if attemptCount >= 10 {
		t.Errorf("Retry count = %d, want < 10 (should be cancelled early)", attemptCount)
	}
}

// TestWithRetry_SuccessFirstAttempt tests immediate success without retry
func TestWithRetry_SuccessFirstAttempt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	config := DefaultRetryConfig()

	attemptCount := 0
	operation := func() error {
		attemptCount++
		return nil // Success immediately
	}

	err := WithRetry(rc, config, operation)

	if err != nil {
		t.Errorf("WithRetry returned error %v, want nil", err)
	}

	if attemptCount != 1 {
		t.Errorf("Attempt count = %d, want 1 (no retry needed)", attemptCount)
	}
}
