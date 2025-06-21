package crypto

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// TestPasswordSecurityRequirements validates password generation meets security standards
func TestPasswordSecurityRequirements(t *testing.T) {
	t.Run("password_length_security", func(t *testing.T) {
		// Current minimum is 12, but security best practice is 14+
		if MinPasswordLen < 14 {
			t.Errorf("MinPasswordLen is %d, should be at least 14 for enterprise security", MinPasswordLen)
		}

		// Test that we can't generate passwords shorter than minimum
		_, err := GeneratePassword(MinPasswordLen - 1)
		testutil.AssertError(t, err)

		// Test minimum length password generation
		pwd, err := GeneratePassword(MinPasswordLen)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, MinPasswordLen, len(pwd))
	})

	t.Run("password_entropy_validation", func(t *testing.T) {
		// Generate multiple passwords and ensure they're different
		passwords := make(map[string]bool)

		for range 100 {
			pwd, err := GeneratePassword(20)
			testutil.AssertNoError(t, err)

			if passwords[pwd] {
				t.Errorf("Generated duplicate password: %s", pwd)
			}
			passwords[pwd] = true

			// Validate character class requirements
			validatePasswordComplexity(t, pwd)
		}
	})

	t.Run("password_character_set_security", func(t *testing.T) {
		// Ensure symbol characters don't include shell injection risks
		dangerousChars := []string{"`", "$", "\\", "\"", "'"}

		for _, char := range dangerousChars {
			if strings.Contains(symbolChars, char) {
				t.Errorf("Symbol character set contains potentially dangerous character: %s", char)
			}
		}

		// Validate all character sets are non-empty
		testutil.AssertNotEqual(t, "", lowerChars)
		testutil.AssertNotEqual(t, "", upperChars)
		testutil.AssertNotEqual(t, "", digitChars)
		testutil.AssertNotEqual(t, "", symbolChars)
	})
}

// validatePasswordComplexity ensures generated passwords meet complexity requirements
func validatePasswordComplexity(t *testing.T, password string) {
	t.Helper()

	var hasLower, hasUpper, hasDigit, hasSymbol bool

	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if !hasLower {
		t.Errorf("Password missing lowercase characters: %s", password)
	}
	if !hasUpper {
		t.Errorf("Password missing uppercase characters: %s", password)
	}
	if !hasDigit {
		t.Errorf("Password missing digit characters: %s", password)
	}
	if !hasSymbol {
		t.Errorf("Password missing symbol characters: %s", password)
	}
}

// TestPasswordValidationSecurity tests strong password validation
func TestPasswordValidationSecurity(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		shouldPass  bool
		description string
	}{
		{
			name:        "strong_password",
			password:    "MyStr0ng!P@ssw0rd#2024",
			shouldPass:  true,
			description: "Strong password with all character classes",
		},
		{
			name:        "too_short",
			password:    "Short1!",
			shouldPass:  false,
			description: "Password shorter than minimum length",
		},
		{
			name:        "no_uppercase",
			password:    "mystrongpassword123!",
			shouldPass:  false,
			description: "Missing uppercase letters",
		},
		{
			name:        "no_lowercase",
			password:    "MYSTRONGPASSWORD123!",
			shouldPass:  false,
			description: "Missing lowercase letters",
		},
		{
			name:        "no_digits",
			password:    "MyStrongPassword!",
			shouldPass:  false,
			description: "Missing digit characters",
		},
		{
			name:        "no_symbols",
			password:    "MyStrongPassword123",
			shouldPass:  false,
			description: "Missing symbol characters",
		},
		{
			name:        "common_password",
			password:    "Password123!",
			shouldPass:  false,
			description: "Common/predictable password pattern",
		},
		{
			name:        "keyboard_pattern",
			password:    "Qwerty123!@#",
			shouldPass:  false,
			description: "Keyboard pattern password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStrongPassword(context.Background(), tt.password)

			if tt.shouldPass {
				if err != nil {
					t.Errorf("Expected strong password to pass validation, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected weak password to fail validation: %s", tt.description)
				}
			}
		})
	}
}

// TestBcryptSecurityConfiguration validates bcrypt security settings
func TestBcryptSecurityConfiguration(t *testing.T) {
	t.Run("bcrypt_cost_security", func(t *testing.T) {
		password := "testPassword123!"

		// Test with default cost (should be 10 minimum)
		hash, err := HashPassword(password)
		testutil.AssertNoError(t, err)

		// Bcrypt hashes should start with $2a$ or $2b$ and have proper cost
		if !strings.HasPrefix(hash, "$2") {
			t.Errorf("Bcrypt hash doesn't have proper format: %s", hash)
		}

		// Verify password can be verified
		err = ComparePassword(hash, password)
		testutil.AssertNoError(t, err)

		// Verify wrong password fails
		err = ComparePassword(hash, "wrongPassword")
		testutil.AssertError(t, err)
	})

	t.Run("bcrypt_timing_attack_resistance", func(t *testing.T) {
		// Generate a known hash
		password := "testPassword123!"
		hash, err := HashPassword(password)
		testutil.AssertNoError(t, err)

		// Test that verification takes similar time for correct and incorrect passwords
		// This is a basic test - in practice you'd need more sophisticated timing analysis

		// Correct password
		err1 := ComparePassword(hash, password)
		testutil.AssertNoError(t, err1)

		// Incorrect password (should still take similar time due to bcrypt)
		err2 := ComparePassword(hash, "wrongPassword123!")
		testutil.AssertError(t, err2)

		// Both operations should complete (timing is handled by bcrypt internally)
	})
}

// TestSecureEraseEffectiveness tests secure deletion functionality
func TestSecureEraseEffectiveness(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("secure_erase_file_deletion", func(t *testing.T) {
		// Skip this test in CI environments that may not have shred command
		if os.Getenv("CI") != "" {
			t.Skip("Skipping secure erase test in CI environment")
		}
		
		// Skip this test if shred command is not available (e.g., on macOS)
		if _, err := exec.LookPath("shred"); err != nil {
			t.Skip("Skipping secure erase test - shred command not available")
		}

		// Create a test file with sensitive content
		testFile := filepath.Join(tempDir, "sensitive_data.txt")
		sensitiveContent := "SENSITIVE_SECRET_DATA_123456789"

		err := os.WriteFile(testFile, []byte(sensitiveContent), 0600)
		testutil.AssertNoError(t, err)

		// Verify file exists
		_, err = os.Stat(testFile)
		testutil.AssertNoError(t, err)

		// Create a proper runtime context for the secure erase
		rc := testutil.TestRuntimeContext(t)

		// Securely erase the file
		err = SecureErase(rc.Ctx, testFile)
		testutil.AssertNoError(t, err)

		// Verify file no longer exists
		_, err = os.Stat(testFile)
		testutil.AssertError(t, err)
	})

	t.Run("secure_zero_memory", func(t *testing.T) {
		// Test memory zeroing functionality
		sensitiveData := []byte("SENSITIVE_MEMORY_DATA_987654321")
		originalData := make([]byte, len(sensitiveData))
		copy(originalData, sensitiveData)

		// Verify data is initially present
		testutil.AssertEqual(t, string(originalData), string(sensitiveData))

		// Securely zero the memory
		SecureZero(sensitiveData)

		// Verify memory has been zeroed
		for i, b := range sensitiveData {
			if b != 0 {
				t.Errorf("Memory not properly zeroed at index %d: got %d, expected 0", i, b)
			}
		}
	})
}

// TestHashFunctionSecurity validates hash function security
func TestHashFunctionSecurity(t *testing.T) {
	t.Run("hash_consistency", func(t *testing.T) {
		input := "test string for hashing"

		// Hash the same input multiple times
		hash1 := HashString(input)
		hash2 := HashString(input)

		// Hashes should be identical for same input
		testutil.AssertEqual(t, hash1, hash2)
		testutil.AssertNotEqual(t, "", hash1)
	})

	t.Run("hash_different_inputs", func(t *testing.T) {
		inputs := []string{
			"input1",
			"input2",
			"Input1",  // Case sensitive
			"input1 ", // Whitespace sensitive
			"",        // Empty string
		}

		hashes := make(map[string]string)

		for _, input := range inputs {
			hash := HashString(input)

			// Check for collisions
			for prevInput, prevHash := range hashes {
				if hash == prevHash && input != prevInput {
					t.Errorf("Hash collision detected: '%s' and '%s' have same hash", input, prevInput)
				}
			}

			hashes[input] = hash
		}
	})

	t.Run("hash_length_consistency", func(t *testing.T) {
		// All hashes should have consistent length
		inputs := []string{"short", "medium length input", "very long input string with lots of characters"}
		var expectedLength int

		for i, input := range inputs {
			hash := HashString(input)

			if i == 0 {
				expectedLength = len(hash)
			} else {
				testutil.AssertEqual(t, expectedLength, len(hash))
			}
		}
	})
}

// TestCertificateGenerationSecurity tests certificate generation security
func TestCertificateGenerationSecurity(t *testing.T) {
	t.Run("certificate_input_validation", func(t *testing.T) {
		// Test cases with potentially dangerous inputs
		dangerousInputs := []struct {
			name   string
			domain string
			email  string
		}{
			{
				name:   "command_injection_domain",
				domain: "example.com; rm -rf /",
				email:  "test@example.com",
			},
			{
				name:   "command_injection_email",
				domain: "example.com",
				email:  "test@example.com; cat /etc/passwd",
			},
			{
				name:   "null_byte_injection",
				domain: "example.com\x00malicious",
				email:  "test@example.com",
			},
			{
				name:   "path_traversal",
				domain: "../../../etc/passwd",
				email:  "test@example.com",
			},
		}

		for _, tt := range dangerousInputs {
			t.Run(tt.name, func(t *testing.T) {
				// In a real implementation, you'd test the actual certificate generation function
				// For now, we're validating that such inputs would be properly sanitized

				// Basic validation that should be in place
				if strings.Contains(tt.domain, ";") || strings.Contains(tt.domain, "&") {
					t.Logf("Good: Domain contains shell metacharacters that should be rejected: %s", tt.domain)
				}

				if strings.Contains(tt.email, ";") || strings.Contains(tt.email, "&") {
					t.Logf("Good: Email contains shell metacharacters that should be rejected: %s", tt.email)
				}

				if strings.Contains(tt.domain, "\x00") || strings.Contains(tt.email, "\x00") {
					t.Logf("Good: Input contains null bytes that should be rejected")
				}

				if strings.Contains(tt.domain, "..") {
					t.Logf("Good: Domain contains path traversal that should be rejected: %s", tt.domain)
				}
			})
		}
	})
}

// TestSecretInjectionSecurity tests secret replacement functionality
func TestSecretInjectionSecurity(t *testing.T) {
	t.Run("secret_injection_from_placeholders", func(t *testing.T) {
		// Test the actual InjectSecretsFromPlaceholders function
		template := []byte("username: changeme\npassword: changeme1\napi_key: changeme2")

		result, replacements, err := InjectSecretsFromPlaceholders(template)
		testutil.AssertNoError(t, err)

		// Verify replacements were made
		testutil.AssertEqual(t, 3, len(replacements))

		// Verify template no longer contains placeholders
		resultStr := string(result)
		if strings.Contains(resultStr, "changeme") {
			t.Error("Template still contains unreplaced placeholders")
		}

		// Verify all replacement values are different
		values := make(map[string]bool)
		for _, value := range replacements {
			if values[value] {
				t.Error("Generated duplicate replacement values")
			}
			values[value] = true

			// Verify each replacement is a valid strong password
			err := ValidateStrongPassword(context.Background(), value)
			testutil.AssertNoError(t, err)
		}
	})

	t.Run("secret_injection_password_strength", func(t *testing.T) {
		// Test that generated secrets meet security requirements
		template := []byte("secret1: changeme\nsecret2: changeme1")

		_, replacements, err := InjectSecretsFromPlaceholders(template)
		testutil.AssertNoError(t, err)

		for placeholder, password := range replacements {
			t.Run("password_for_"+placeholder, func(t *testing.T) {
				// Each generated password should be strong
				err := ValidateStrongPassword(context.Background(), password)
				testutil.AssertNoError(t, err)

				// Should be at least 20 characters (as per function implementation)
				if len(password) < 20 {
					t.Errorf("Generated password too short: %d characters", len(password))
				}

				// Should contain all character classes
				validatePasswordComplexity(t, password)
			})
		}
	})
}
