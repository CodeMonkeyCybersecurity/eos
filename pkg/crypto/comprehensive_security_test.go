// pkg/crypto/comprehensive_security_test.go - Comprehensive security tests for cryptographic functions
package crypto

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGeneratePassword_SecurityProperties tests the security properties of password generation
func TestGeneratePassword_SecurityProperties(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
		errMsg  string
	}{
		{
			name:    "minimum_length_password",
			length:  MinPasswordLen,
			wantErr: false,
		},
		{
			name:    "standard_length_password",
			length:  20,
			wantErr: false,
		},
		{
			name:    "long_password",
			length:  50,
			wantErr: false,
		},
		{
			name:    "too_short_password",
			length:  8,
			wantErr: true,
			errMsg:  "password too short",
		},
		{
			name:    "extremely_short_password",
			length:  1,
			wantErr: true,
			errMsg:  "password too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := GeneratePassword(tt.length)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Empty(t, password)
				return
			}

			require.NoError(t, err)
			assert.Len(t, password, tt.length)

			// Verify character class requirements
			assert.True(t, hasCharacterClass(password, lowerChars), "Password missing lowercase characters")
			assert.True(t, hasCharacterClass(password, upperChars), "Password missing uppercase characters")
			assert.True(t, hasCharacterClass(password, digitChars), "Password missing digit characters")
			assert.True(t, hasCharacterClass(password, symbolChars), "Password missing symbol characters")

			// Verify only allowed characters are used
			for _, ch := range password {
				assert.Contains(t, allChars, string(ch), "Password contains disallowed character: %c", ch)
			}

			// Verify password passes our own validation
			err = ValidateStrongPassword(context.Background(), password)
			assert.NoError(t, err, "Generated password should pass validation")
		})
	}
}

// TestGeneratePassword_Uniqueness verifies passwords are unique across generations
func TestGeneratePassword_Uniqueness(t *testing.T) {
	const iterations = 100
	const passwordLength = 16

	passwords := make(map[string]bool, iterations)

	for i := 0; i < iterations; i++ {
		password, err := GeneratePassword(passwordLength)
		require.NoError(t, err)

		// Check for duplicates
		assert.False(t, passwords[password], "Generated duplicate password: %s", password)
		passwords[password] = true
	}

	// Should have generated unique passwords
	assert.Len(t, passwords, iterations, "Should generate unique passwords")
}

// TestGeneratePassword_EntropyQuality tests entropy characteristics
func TestGeneratePassword_EntropyQuality(t *testing.T) {
	const iterations = 1000
	const passwordLength = 20

	charFrequency := make(map[rune]int)

	for i := 0; i < iterations; i++ {
		password, err := GeneratePassword(passwordLength)
		require.NoError(t, err)

		for _, ch := range password {
			charFrequency[ch]++
		}
	}

	// Verify we're using a good spread of characters
	totalChars := iterations * passwordLength
	expectedFreq := float64(totalChars) / float64(len(allChars))

	// Allow 50% variance in character frequency (entropy should be reasonably distributed)
	minExpectedFreq := expectedFreq * 0.5
	maxExpectedFreq := expectedFreq * 1.5

	outliers := 0
	for char, freq := range charFrequency {
		freqFloat := float64(freq)
		if freqFloat < minExpectedFreq || freqFloat > maxExpectedFreq {
			outliers++
			t.Logf("Character %c has frequency %d (expected ~%.1f)", char, freq, expectedFreq)
		}
	}

	// Allow up to 10% of characters to be outliers (some variance is expected)
	maxOutliers := len(allChars) / 10
	assert.LessOrEqual(t, outliers, maxOutliers, "Too many characters have extreme frequencies")
}

// TestValidateStrongPassword_Comprehensive tests password validation
func TestValidateStrongPassword_Comprehensive(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid_strong_password",
			password: "MyStrongP@ssw0rd123!",
			wantErr:  false,
		},
		{
			name:     "minimum_length_valid",
			password: "MinLen14!@#$aB",
			wantErr:  false,
		},
		{
			name:     "too_short",
			password: "Short1!",
			wantErr:  true,
			errMsg:   "password too short",
		},
		{
			name:     "missing_uppercase",
			password: "lowercase123!@#",
			wantErr:  true,
			errMsg:   "missing required character class",
		},
		{
			name:     "missing_lowercase",
			password: "UPPERCASE123!@#",
			wantErr:  true,
			errMsg:   "missing required character class",
		},
		{
			name:     "missing_digits",
			password: "UpperLowerCase!@#",
			wantErr:  true,
			errMsg:   "missing required character class",
		},
		{
			name:     "missing_symbols",
			password: "UpperLowerCase123",
			wantErr:  true,
			errMsg:   "missing required character class",
		},
		{
			name:     "only_letters",
			password: "OnlyLettersHereNoSymbolsOrNumbers",
			wantErr:  true,
			errMsg:   "missing required character class",
		},
		{
			name:     "unicode_characters",
			password: "ValidP@ssw0rd123!你好",
			wantErr:  false, // Should still pass since required classes present
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStrongPassword(ctx, tt.password)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPasswordSecurity_EdgeCases tests edge cases and potential security issues
func TestPasswordSecurity_EdgeCases(t *testing.T) {
	t.Run("empty_string", func(t *testing.T) {
		err := ValidateStrongPassword(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password too short")
	})

	t.Run("whitespace_only", func(t *testing.T) {
		err := ValidateStrongPassword(context.Background(), "               ")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing required character class")
	})

	t.Run("control_characters", func(t *testing.T) {
		password := "Valid1!@#ABC" + string(rune(0x00)) + string(rune(0x1F)) + "def"
		err := ValidateStrongPassword(context.Background(), password)
		// Should still pass if other requirements met and length is sufficient
		assert.NoError(t, err)
	})

	t.Run("very_long_password", func(t *testing.T) {
		// Test extremely long password
		longPassword := strings.Repeat("A1!", 100) + "a" // 301 chars total
		err := ValidateStrongPassword(context.Background(), longPassword)
		assert.NoError(t, err)
	})
}

// TestRandomChar_Security tests the randomChar function for security properties
func TestRandomChar_Security(t *testing.T) {
	const iterations = 10000
	charset := "abcdefghijklmnopqrstuvwxyz"

	frequency := make(map[byte]int)

	for i := 0; i < iterations; i++ {
		char, err := randomChar(charset)
		require.NoError(t, err)

		// Verify character is from the correct charset
		assert.Contains(t, charset, string(char))
		frequency[char]++
	}

	// Verify all characters in charset were used (with high probability)
	for _, ch := range []byte(charset) {
		assert.Greater(t, frequency[ch], 0, "Character %c was never selected", ch)
	}

	// Check distribution is reasonably uniform
	expectedFreq := float64(iterations) / float64(len(charset))
	for ch, freq := range frequency {
		// Allow significant variance due to randomness
		assert.Greater(t, float64(freq), expectedFreq*0.5,
			"Character %c frequency %d too low (expected ~%.1f)", ch, freq, expectedFreq)
		assert.Less(t, float64(freq), expectedFreq*1.5,
			"Character %c frequency %d too high (expected ~%.1f)", ch, freq, expectedFreq)
	}
}

// TestShuffle_Security tests the shuffle function
func TestShuffle_Security(t *testing.T) {
	original := []byte("abcdefghijklmnop")

	// Test multiple shuffles to verify randomness
	const shuffleCount = 100
	shuffleResults := make(map[string]int)

	for i := 0; i < shuffleCount; i++ {
		data := make([]byte, len(original))
		copy(data, original)

		err := shuffle(data)
		require.NoError(t, err)

		// Verify all original characters are still present
		assert.ElementsMatch(t, original, data, "Shuffle should preserve all characters")

		// Track different arrangements
		shuffleResults[string(data)]++
	}

	// Should produce multiple different arrangements
	assert.Greater(t, len(shuffleResults), shuffleCount/2,
		"Shuffle should produce varied arrangements")

	// No single arrangement should dominate
	for arrangement, count := range shuffleResults {
		assert.LessOrEqual(t, count, shuffleCount/4,
			"Arrangement %s appears too frequently (%d times)", arrangement, count)
	}
}

// TestPasswordGeneration_CryptoRandomness verifies cryptographic randomness
func TestPasswordGeneration_CryptoRandomness(t *testing.T) {
	// Verify we're using crypto/rand not math/rand
	// This is a bit tricky to test directly, but we can test statistical properties

	const iterations = 1000
	firstChars := make(map[byte]int)

	for i := 0; i < iterations; i++ {
		password, err := GeneratePassword(16)
		require.NoError(t, err)

		firstChars[password[0]]++
	}

	// Should see good distribution in first characters
	// (This would fail if using predictable randomness)
	assert.Greater(t, len(firstChars), 20, "Should have good variety in first characters")
}

// TestSecurityConstants verifies security-related constants
func TestSecurityConstants(t *testing.T) {
	t.Run("minimum_password_length", func(t *testing.T) {
		// 14 is considered minimum for strong passwords
		assert.GreaterOrEqual(t, MinPasswordLen, 12, "Minimum password length too low")
		assert.Equal(t, 14, MinPasswordLen, "Minimum password length should be 14")
	})

	t.Run("character_sets", func(t *testing.T) {
		// Verify character sets contain expected characters
		assert.Len(t, lowerChars, 26, "Should have all lowercase letters")
		assert.Len(t, upperChars, 26, "Should have all uppercase letters")
		assert.Len(t, digitChars, 10, "Should have all digits")
		assert.Greater(t, len(symbolChars), 15, "Should have sufficient symbols")

		// Verify no dangerous characters
		assert.NotContains(t, symbolChars, "$", "Should not contain $ to prevent shell injection")
		assert.NotContains(t, symbolChars, "`", "Should not contain backtick")
		assert.NotContains(t, symbolChars, "\\", "Should not contain backslash")
	})

	t.Run("all_chars_combination", func(t *testing.T) {
		expectedLen := len(lowerChars) + len(upperChars) + len(digitChars) + len(symbolChars)
		assert.Len(t, allChars, expectedLen, "allChars should contain all character sets")

		// Verify allChars contains all individual sets
		for _, ch := range lowerChars {
			assert.Contains(t, allChars, string(ch))
		}
		for _, ch := range upperChars {
			assert.Contains(t, allChars, string(ch))
		}
		for _, ch := range digitChars {
			assert.Contains(t, allChars, string(ch))
		}
		for _, ch := range symbolChars {
			assert.Contains(t, allChars, string(ch))
		}
	})
}

// Helper function to check if a password contains characters from a specific class
func hasCharacterClass(password, charset string) bool {
	for _, ch := range password {
		if strings.Contains(charset, string(ch)) {
			return true
		}
	}
	return false
}

// BenchmarkGeneratePassword benchmarks password generation performance
func BenchmarkGeneratePassword(b *testing.B) {
	lengths := []int{14, 20, 32, 50}

	for _, length := range lengths {
		b.Run(fmt.Sprintf("length_%d", length), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := GeneratePassword(length)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkValidateStrongPassword benchmarks password validation performance
func BenchmarkValidateStrongPassword(b *testing.B) {
	ctx := context.Background()
	passwords := []string{
		"ShortButStrong1!",
		"MediumLengthPassword123!@#",
		"VeryLongPasswordWithLotsOfCharacters123!@#$%^&*()",
	}

	for _, password := range passwords {
		b.Run(fmt.Sprintf("len_%d", len(password)), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := ValidateStrongPassword(ctx, password)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestConcurrentPasswordGeneration tests thread safety
func TestConcurrentPasswordGeneration(t *testing.T) {
	const goroutines = 10
	const iterations = 100

	results := make(chan string, goroutines*iterations)
	errors := make(chan error, goroutines*iterations)

	// Launch multiple goroutines generating passwords
	for g := 0; g < goroutines; g++ {
		go func() {
			for i := 0; i < iterations; i++ {
				password, err := GeneratePassword(16)
				if err != nil {
					errors <- err
					return
				}
				results <- password
			}
		}()
	}

	// Collect results
	passwords := make(map[string]bool)
	for i := 0; i < goroutines*iterations; i++ {
		select {
		case password := <-results:
			// Check for duplicates (should be extremely rare)
			assert.False(t, passwords[password], "Concurrent generation produced duplicate")
			passwords[password] = true
		case err := <-errors:
			t.Fatalf("Error in concurrent generation: %v", err)
		}
	}

	assert.Len(t, passwords, goroutines*iterations, "Should generate unique passwords concurrently")
}

// TestPasswordValidation_SecurityEdgeCases tests edge cases that might bypass security
func TestPasswordValidation_SecurityEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("repetitive_patterns", func(t *testing.T) {
		// Even with repetitive patterns, should pass if requirements met
		password := "AAaabbcc11!!@@"
		err := ValidateStrongPassword(ctx, password)
		assert.NoError(t, err, "Should pass even with patterns if requirements met")
	})

	t.Run("sequential_characters", func(t *testing.T) {
		password := "ABCDefgh123!@#"
		err := ValidateStrongPassword(ctx, password)
		assert.NoError(t, err, "Should pass with sequential characters")
	})

	t.Run("common_substitutions", func(t *testing.T) {
		password := "P@ssw0rd123!"
		err := ValidateStrongPassword(ctx, password)
		assert.NoError(t, err, "Should pass common substitution patterns")
	})
}
