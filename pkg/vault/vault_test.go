package vault

import (
	"os"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestGet(t *testing.T) {
	tests := []testutil.TableTest[struct {
		key      string
		envVar   string
		envValue string
		want     string
		wantErr  bool
	}]{
		{
			Name: "valid key with value",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "test-key",
				envVar:   "VAULT_TEST_KEY",
				envValue: "secret-value",
				want:     "secret-value",
				wantErr:  false,
			},
		},
		{
			Name: "key with slashes",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "path/to/secret",
				envVar:   "VAULT_PATH_TO_SECRET",
				envValue: "nested-secret",
				want:     "nested-secret",
				wantErr:  false,
			},
		},
		{
			Name: "key with hyphens",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "my-secret-key",
				envVar:   "VAULT_MY_SECRET_KEY",
				envValue: "hyphenated-value",
				want:     "hyphenated-value",
				wantErr:  false,
			},
		},
		{
			Name: "empty key",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "",
				envVar:   "",
				envValue: "",
				want:     "",
				wantErr:  true,
			},
		},
		{
			Name: "key not in environment",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "nonexistent-key",
				envVar:   "",
				envValue: "",
				want:     "",
				wantErr:  true,
			},
		},
		{
			Name: "key with special characters",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "key@with#special$chars!",
				envVar:   "VAULT_KEY_WITH_SPECIAL_CHARS_",
				envValue: "special-value",
				want:     "special-value",
				wantErr:  false,
			},
		},
		{
			Name: "key with dots",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "app.config.database.url",
				envVar:   "VAULT_APP_CONFIG_DATABASE_URL",
				envValue: "postgres://localhost:5432/db",
				want:     "postgres://localhost:5432/db",
				wantErr:  false,
			},
		},
		{
			Name: "empty environment value",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "empty-value-key",
				envVar:   "VAULT_EMPTY_VALUE_KEY",
				envValue: "",
				want:     "",
				wantErr:  true,
			},
		},
		{
			Name: "key with unicode characters",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "key-with-unicode-αβγ",
				envVar:   "VAULT_KEY_WITH_UNICODE____",
				envValue: "unicode-secret",
				want:     "unicode-secret",
				wantErr:  false,
			},
		},
		{
			Name: "key with consecutive hyphens",
			Input: struct {
				key      string
				envVar   string
				envValue string
				want     string
				wantErr  bool
			}{
				key:      "key--with---multiple----hyphens",
				envVar:   "VAULT_KEY__WITH___MULTIPLE____HYPHENS",
				envValue: "hyphen-value",
				want:     "hyphen-value",
				wantErr:  false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			// Set up environment - use Eos_SECRET_ prefix that the actual implementation uses
			if tc.Input.envVar != "" && tc.Input.envValue != "" {
				actualEnvVar := "Eos_SECRET_" + sanitizeKey(tc.Input.key)
				testutil.WithEnvVar(t, actualEnvVar, tc.Input.envValue)
			}

			// Test Get function
			got, err := Get(tc.Input.key)

			// Check error
			if tc.Input.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, tc.Input.want, got)
			}
		})
	}
}

func TestSanitizeKey(t *testing.T) {
	tests := []testutil.TableTest[struct {
		input    string
		expected string
	}]{
		{
			Name: "simple key",
			Input: struct {
				input    string
				expected string
			}{
				input:    "simple",
				expected: "SIMPLE",
			},
		},
		{
			Name: "key with hyphens",
			Input: struct {
				input    string
				expected string
			}{
				input:    "my-secret-key",
				expected: "MY-SECRET-KEY",
			},
		},
		{
			Name: "key with slashes",
			Input: struct {
				input    string
				expected string
			}{
				input:    "path/to/secret",
				expected: "PATH_TO_SECRET",
			},
		},
		{
			Name: "key with dots",
			Input: struct {
				input    string
				expected string
			}{
				input:    "app.config.db",
				expected: "APP.CONFIG.DB",
			},
		},
		{
			Name: "key with special characters",
			Input: struct {
				input    string
				expected string
			}{
				input:    "key@with#special$chars!",
				expected: "KEY@WITH#SPECIAL$CHARS!",
			},
		},
		{
			Name: "key with spaces",
			Input: struct {
				input    string
				expected string
			}{
				input:    "key with spaces",
				expected: "KEY WITH SPACES",
			},
		},
		{
			Name: "key with unicode",
			Input: struct {
				input    string
				expected string
			}{
				input:    "key-αβγ-test",
				expected: "KEY-ΑΒΓ-TEST",
			},
		},
		{
			Name: "empty key",
			Input: struct {
				input    string
				expected string
			}{
				input:    "",
				expected: "",
			},
		},
		{
			Name: "key with consecutive special chars",
			Input: struct {
				input    string
				expected string
			}{
				input:    "key@@##$$test",
				expected: "KEY@@##$$TEST",
			},
		},
		{
			Name: "already uppercase",
			Input: struct {
				input    string
				expected string
			}{
				input:    "ALREADY-UPPER",
				expected: "ALREADY-UPPER",
			},
		},
		{
			Name: "mixed case",
			Input: struct {
				input    string
				expected string
			}{
				input:    "MiXeD-CaSe-KeY",
				expected: "MIXED-CASE-KEY",
			},
		},
		{
			Name: "numeric key",
			Input: struct {
				input    string
				expected string
			}{
				input:    "key123",
				expected: "KEY123",
			},
		},
		{
			Name: "key starting with number",
			Input: struct {
				input    string
				expected string
			}{
				input:    "123key",
				expected: "123KEY",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			got := sanitizeKey(tc.Input.input)
			testutil.AssertEqual(t, tc.Input.expected, got)
		})
	}
}

func TestGetIntegration(t *testing.T) {
	// Test concurrent access to Get
	t.Run("concurrent access", func(t *testing.T) {
		// Set up test environment variables
		testKeys := map[string]string{
			"concurrent-1": "value-1",
			"concurrent-2": "value-2",
			"concurrent-3": "value-3",
		}

		for key, value := range testKeys {
			envVar := "Eos_SECRET_" + sanitizeKey(key)
			testutil.WithEnvVar(t, envVar, value)
		}

		// Run concurrent Get operations
		testutil.ParallelTest(t, 10, func(t *testing.T, i int) {
			key := "concurrent-" + string(rune('1'+(i%3)))
			expectedValue := "value-" + string(rune('1'+(i%3)))

			value, err := Get(key)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, expectedValue, value)
		})
	})

	// Test environment variable manipulation resistance
	t.Run("environment manipulation", func(t *testing.T) {
		key := "test-env-key"
		value := "original-value"
		envVar := "Eos_SECRET_" + sanitizeKey(key)

		// Set initial value
		testutil.WithEnvVar(t, envVar, value)

		// Get the value
		got1, err := Get(key)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, value, got1)

		// Try to manipulate the environment during test
		_ = os.Setenv(envVar, "manipulated-value")

		// Get should still work with new value
		got2, err := Get(key)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, "manipulated-value", got2)
	})
}

func TestGetSecurityCases(t *testing.T) {
	// Test for potential security issues
	securityTests := []struct {
		name     string
		key      string
		envValue string
		check    func(t *testing.T, value string, err error)
	}{
		{
			name:     "path traversal attempt",
			key:      "../../../etc/passwd",
			envValue: "should-not-access",
			check: func(t *testing.T, value string, err error) {
				// Should still work but with sanitized key
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, "should-not-access", value)
			},
		},
		{
			name:     "null byte injection",
			key:      "key\x00injection",
			envValue: "test-value",
			check: func(t *testing.T, value string, err error) {
				// Should handle null bytes safely
				testutil.AssertNoError(t, err)
			},
		},
		{
			name:     "command injection attempt",
			key:      "key`whoami`",
			envValue: "safe-value",
			check: func(t *testing.T, value string, err error) {
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, "safe-value", value)
			},
		},
		{
			name:     "environment variable injection",
			key:      "key${PATH}",
			envValue: "another-safe-value",
			check: func(t *testing.T, value string, err error) {
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, "another-safe-value", value)
			},
		},
		{
			name:     "very long key",
			key:      string(make([]byte, 1000)),
			envValue: "long-key-value",
			check: func(t *testing.T, value string, err error) {
				// Should handle long keys without issues
				testutil.AssertNoError(t, err)
			},
		},
	}

	for _, tc := range securityTests {
		t.Run(tc.name, func(t *testing.T) {
			envVar := "Eos_SECRET_" + sanitizeKey(tc.key)
			if tc.envValue != "" {
				testutil.WithEnvVar(t, envVar, tc.envValue)
			}

			value, err := Get(tc.key)
			tc.check(t, value, err)
		})
	}
}

func BenchmarkGet(b *testing.B) {
	// Set up test environment
	key := "benchmark-key"
	envVar := "Eos_SECRET_" + sanitizeKey(key)
	_ = os.Setenv(envVar, "benchmark-value")
	defer os.Unsetenv(envVar)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Get(key)
	}
}

func BenchmarkSanitizeKey(b *testing.B) {
	keys := []string{
		"simple-key",
		"path/to/secret",
		"key@with#special$chars!",
		"very-long-key-with-many-hyphens-and-slashes/and/paths",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeKey(keys[i%len(keys)])
	}
}
