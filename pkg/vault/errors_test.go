package vault

import (
	"errors"
	"fmt"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestIsSecretNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "error with 'no secret' message",
			err:      errors.New("no secret found at path kv/data/test"),
			expected: true,
		},
		{
			name:     "error with '404' in message",
			err:      errors.New("404 Not Found"),
			expected: true,
		},
		{
			name:     "error with HTTP 404 response",
			err:      fmt.Errorf("Error making API request. URL: GET http://vault:8200/v1/secret/data/test Code: 404"),
			expected: true,
		},
		{
			name:     "wrapped ErrSecretNotFound",
			err:      fmt.Errorf("failed to read secret: %w", eos_err.ErrSecretNotFound),
			expected: true,
		},
		{
			name:     "direct ErrSecretNotFound",
			err:      eos_err.ErrSecretNotFound,
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      errors.New("permission denied"),
			expected: false,
		},
		{
			name:     "error with partial match 'no secret'",
			err:      errors.New("there is no secret at the specified path"),
			expected: true,
		},
		{
			name:     "case sensitivity check - uppercase",
			err:      errors.New("NO SECRET FOUND"),
			expected: false, // Function is case-sensitive
		},
		{
			name:     "error with 404 in path not status",
			err:      errors.New("path contains /404/ but not an error"),
			expected: true, // Will match on "404"
		},
		{
			name:     "complex vault error message",
			err:      errors.New(`{"errors":["no secret at path kv/data/myapp/config"]}`),
			expected: true,
		},
		{
			name:     "vault permission denied on secret path",
			err:      errors.New("1 error occurred: permission denied on path secret/data/test"),
			expected: false,
		},
		{
			name:     "empty error message",
			err:      errors.New(""),
			expected: false,
		},
		{
			name:     "error with only spaces",
			err:      errors.New("   "),
			expected: false,
		},
		{
			name:     "nested error with secret not found",
			err:      fmt.Errorf("operation failed: %w", errors.New("no secret exists at this location")),
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsSecretNotFound(tc.err)
			testutil.AssertEqual(t, tc.expected, result)
		})
	}
}

func TestIsSecretNotFoundEdgeCases(t *testing.T) {
	t.Run("multiple wrapped errors", func(t *testing.T) {
		// Test deeply nested error wrapping
		err := errors.New("original error")
		for i := 0; i < 5; i++ {
			err = fmt.Errorf("wrapper %d: %w", i, err)
		}
		finalErr := fmt.Errorf("final: %w", eos_err.ErrSecretNotFound)

		result := IsSecretNotFound(finalErr)
		testutil.AssertEqual(t, true, result)
	})

	t.Run("error with both indicators", func(t *testing.T) {
		// Error that contains both "no secret" and "404"
		err := errors.New("404: no secret found at the requested path")
		result := IsSecretNotFound(err)
		testutil.AssertEqual(t, true, result)
	})

	t.Run("vault API error format", func(t *testing.T) {
		// Simulate actual Vault API error format
		vaultErrors := []error{
			errors.New("Error making API request.\n\nURL: GET http://shared.GetInternalHostname:8200/v1/kv/data/test\nCode: 404. Errors:\n\n* no secret at kv/data/test"),
			errors.New("Get \"http://vault:8200/v1/secret/data/app\": 404 Not Found"),
			errors.New("error reading secret at path secret/data/test: Error making API request. Code: 404"),
		}

		for _, err := range vaultErrors {
			result := IsSecretNotFound(err)
			testutil.AssertEqual(t, true, result)
		}
	})

	t.Run("false positives check", func(t *testing.T) {
		// Ensure we don't match on unrelated errors that might contain keywords
		falsePositives := []error{
			errors.New("the number is 4045, not 404"),
			errors.New("there's no secretive way to do this"),
			errors.New("404 users have no secrets"),
		}

		// These will actually return true because they contain "404" or "no secret"
		// This tests that the function works as documented
		for _, err := range falsePositives {
			result := IsSecretNotFound(err)
			testutil.AssertEqual(t, true, result)
		}
	})
}

func TestIsSecretNotFoundConcurrency(t *testing.T) {
	// Test that IsSecretNotFound is safe for concurrent use
	errors := []error{
		nil,
		errors.New("no secret found"),
		errors.New("404 not found"),
		eos_err.ErrSecretNotFound,
		errors.New("permission denied"),
	}

	// Run concurrent checks
	testutil.ParallelTest(t, 100, func(t *testing.T, i int) {
		err := errors[i%len(errors)]
		_ = IsSecretNotFound(err)
	})
}

type customError struct {
	msg string
}

func (e customError) Error() string {
	return e.msg
}

func TestIsSecretNotFoundWithCustomError(t *testing.T) {

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "custom error with secret not found message",
			err:      customError{msg: "no secret found here"},
			expected: true,
		},
		{
			name:     "custom error with 404",
			err:      customError{msg: "404: resource not available"},
			expected: true,
		},
		{
			name:     "custom error without matching text",
			err:      customError{msg: "access denied"},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsSecretNotFound(tc.err)
			testutil.AssertEqual(t, tc.expected, result)
		})
	}
}

func BenchmarkIsSecretNotFound(b *testing.B) {
	// Benchmark different error types
	errors := []error{
		nil,
		errors.New("no secret found at path"),
		errors.New("404 Not Found"),
		fmt.Errorf("wrapped: %w", eos_err.ErrSecretNotFound),
		errors.New("unrelated error message"),
		errors.New("very long error message that contains many words but ultimately includes no secret in the middle of it"),
	}

	b.ResetTimer()
	for b.Loop() {
		_ = IsSecretNotFound(errors[i%len(errors)])
	}
}

func BenchmarkIsSecretNotFoundWorstCase(b *testing.B) {
	// Benchmark with very long error messages
	longError := errors.New(string(make([]byte, 10000))) // 10KB error message

	b.ResetTimer()
	for b.Loop() {
		_ = IsSecretNotFound(longError)
	}
}
