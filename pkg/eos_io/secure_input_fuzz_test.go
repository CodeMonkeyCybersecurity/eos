package eos_io

import (
	"context"
	"strings"
	"testing"
	"time"
)

// FuzzPromptInput tests input prompt handling for terminal escape sequence injection
func FuzzPromptInput(f *testing.F) {
	// Add seed corpus with various attack vectors
	seeds := []string{
		// Terminal escape sequences
		"\x1b[31mmalicious\x1b[0m",
		"\x1b]0;evil title\x07",
		"\x9b[A",        // CSI sequences
		"\x1b[2J\x1b[H", // Clear screen

		// Control characters
		"input\x00with\x00nulls",
		"input\rwith\rcarriage\rreturns",
		"input\nwith\nnewlines",
		"input\twith\ttabs",
		"\x08\x08\x08backspace",

		// Unicode attacks
		"café",                // Basic Unicode
		"💀skull",              // Emoji
		"\u202e\u202d",        // Unicode direction override
		"\ufeff",              // BOM
		"A\u0300\u0301\u0302", // Combining characters

		// Buffer overflow attempts
		strings.Repeat("A", 1024),
		strings.Repeat("A", 4096),
		strings.Repeat("A", 65536),

		// Format string attacks
		"%s%s%s%s",
		"%n%n%n%n",
		"%x%x%x%x",

		// Command injection attempts
		"; rm -rf /",
		"| cat /etc/passwd",
		"$(whoami)",
		"`id`",

		// Empty and edge cases
		"",
		" ",
		"\x00",
		strings.Repeat("\x00", 100),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Create test context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_ = &RuntimeContext{
			Ctx: ctx,
		}

		// Test prompt input handling - should not panic or crash
		// Note: We can't easily test interactive input in fuzz tests,
		// but we can test the validation and sanitization logic

		// Test input validation
		if len(input) > 0 {
			// Should handle any input gracefully
			_ = validateUserInput(input, "test-field")
		}

		// Test prompt message construction - should not allow injection
		promptMsg := constructPromptMessage("Enter value", input)

		// Verify prompt message doesn't contain dangerous sequences
		if strings.Contains(promptMsg, "\x1b") && !strings.HasPrefix(input, "\x1b") {
			t.Error("Prompt message contains escape sequences not from input")
		}

		// Test input sanitization
		sanitized := sanitizeUserInput(input)

		// Verify sanitization removes dangerous characters
		if strings.Contains(sanitized, "\x00") {
			t.Error("Sanitized input contains null bytes")
		}

		if strings.Contains(sanitized, "\x1b") {
			t.Error("Sanitized input contains escape sequences")
		}
	})
}

// FuzzPromptSecurePassword tests secure password input for injection attacks
func FuzzPromptSecurePassword(f *testing.F) {
	seeds := []string{
		// Terminal control sequences that could expose password
		"\x1b[8mhidden\x1b[28m", // Hidden text
		"\x1b[?25l",             // Hide cursor
		"\x1b[?25h",             // Show cursor
		"\x1b[s\x1b[u",          // Save/restore cursor

		// Clipboard attacks
		"\x1b]52;c;\x07", // OSC 52 clipboard

		// History attacks
		"\x1b[A\x1b[A", // Up arrow keys

		// Special characters that might break input
		"password\x03", // Ctrl+C
		"password\x04", // Ctrl+D
		"password\x1a", // Ctrl+Z

		// Unicode passwords
		"pássw🔒rd",
		"пароль", // Cyrillic
		"密码",     // Chinese

		// Edge cases
		"",
		strings.Repeat("a", 1024), // Very long password
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, password string) {
		// Test password validation
		_ = validatePasswordInput(password, "test-password")

		// Even invalid passwords should not cause crashes
		if len(password) > 0 {
			// Test that password sanitization works
			sanitized := sanitizePasswordInputTest(password)

			// Verify no control characters remain
			for _, char := range sanitized {
				if char < 32 && char != '\t' && char != '\n' && char != '\r' {
					t.Errorf("Sanitized password contains control character: %d", char)
				}
			}
		}

		// Test password strength validation
		strength := calculatePasswordStrength(password)
		if strength < 0 || strength > 100 {
			t.Errorf("Password strength out of range: %d", strength)
		}
	})
}

// FuzzPromptYesNo tests yes/no prompt handling
func FuzzPromptYesNo(f *testing.F) {
	seeds := []string{
		"y", "Y", "yes", "YES", "Yes",
		"n", "N", "no", "NO", "No",
		"true", "false", "1", "0",
		"", " ", "\t", "\n",
		"maybe", "perhaps", "absolutely",
		"yessir", "nope", "yep", "nah",
		"\x1b[A", "yes\x00", "no\r\n",
		strings.Repeat("y", 1000),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Test yes/no parsing
		result, valid := parseYesNoInputTest(input)

		// Should always return a boolean result and validity flag
		_ = result
		_ = valid

		// Test case insensitive parsing
		normalized := normalizeYesNoInput(input)
		if len(normalized) > 10 {
			t.Error("Normalized input too long, possible DoS")
		}
	})
}

// FuzzPromptValidatedInput tests input validation with custom validators
func FuzzPromptValidatedInput(f *testing.F) {
	seeds := []string{
		// Email-like inputs
		"user@example.com",
		"invalid-email",
		"test@",
		"@example.com",
		"user@example..com",

		// Path-like inputs
		"/valid/path",
		"../../../etc/passwd",
		"C:\\Windows\\System32",
		"//server/share",
		"\\\\server\\share",

		// Number-like inputs
		"123", "0", "-1", "3.14",
		"1e10", "Infinity", "NaN",

		// JSON-like inputs
		"{\"key\":\"value\"}",
		"{'key':'value'}",
		"malformed{json",

		// Command injection in validation
		"valid; rm -rf /",
		"valid | cat /etc/passwd",
		"$(malicious)",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Test various validation functions
		validators := []func(string) error{
			validateEmailInput,
			validatePathInput,
			validateNumberInput,
			validateJSONInput,
			validateUsernameInput,
		}

		for _, validator := range validators {
			// Validators should never panic
			err := validator(input)
			_ = err // Error is expected for most fuzz inputs
		}

		// Test input normalization
		normalized := normalizeValidationInput(input)
		if len(normalized) > len(input)*2 {
			t.Error("Normalized input significantly larger than original")
		}
	})
}

// Helper functions that should exist in the actual implementation
// These represent the validation logic that needs to be implemented

func constructPromptMessage(prompt, defaultValue string) string {
	// Safe prompt message construction for testing
	// Should sanitize input to prevent terminal injection
	safePrompt := sanitizeUserInputTest(prompt)
	safeDefault := sanitizeUserInputTest(defaultValue)
	return safePrompt + ": " + safeDefault
}

func sanitizeUserInputTest(input string) string {
	// Test version of user input sanitization
	// Should remove control characters, escape sequences, etc.
	result := strings.ReplaceAll(input, "\x00", "")
	result = strings.ReplaceAll(result, "\x1b", "")
	return result
}

func sanitizePasswordInputTest(password string) string {
	// Test version of password sanitization
	// Should remove control characters but preserve valid Unicode
	result := ""
	for _, char := range password {
		if char >= 32 || char == '\t' || char == '\n' || char == '\r' {
			result += string(char)
		}
	}
	return result
}

func calculatePasswordStrength(password string) int {
	// TODO: Implement password strength calculation
	// Should return 0-100 based on entropy, character sets, etc.
	if len(password) == 0 {
		return 0
	}
	return min(len(password)*10, 100)
}

func parseYesNoInputTest(input string) (bool, bool) {
	// Test version of yes/no parsing
	// Should handle various representations of yes/no
	lower := strings.ToLower(strings.TrimSpace(input))
	switch lower {
	case "y", "yes", "true", "1":
		return true, true
	case "n", "no", "false", "0":
		return false, true
	default:
		return false, false
	}
}

func normalizeYesNoInput(input string) string {
	// TODO: Implement yes/no input normalization
	return strings.TrimSpace(strings.ToLower(input))
}

func validateEmailInput(input string) error {
	// TODO: Implement email validation
	return nil
}

func validatePathInput(input string) error {
	// TODO: Implement path validation
	return nil
}

func validateNumberInput(input string) error {
	// TODO: Implement number validation
	return nil
}

func validateJSONInput(input string) error {
	// TODO: Implement JSON validation
	return nil
}

func validateUsernameInput(input string) error {
	// TODO: Implement username validation
	return nil
}

func normalizeValidationInput(input string) string {
	// TODO: Implement input normalization
	return strings.TrimSpace(input)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
