// pkg/crypto/passwd.go

package crypto

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"
)

// Constants and charsets for password generation
const MinPasswordLen = 14

// These should come from your shared package or be defined here directly
var (
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars  = "0123456789"
	symbolChars = "!@#%^&*()-_=+[]{}|;:,.<>?/" // Removed $ to prevent shell injection
	allChars    = lowerChars + upperChars + digitChars + symbolChars

	// Alphanumeric-only characters for maximum compatibility
	// Safe for: URLs, databases, APIs, config files, shells, legacy systems
	// No special chars = no escaping needed anywhere
	alphanumericChars = lowerChars + upperChars + digitChars
)

// GeneratePassword creates a strong random password with at least 1 of each char class.
func GeneratePassword(length int) (string, error) {
	if length < MinPasswordLen {
		return "", errors.New("password too short: min length " + fmt.Sprintf("%d", MinPasswordLen))
	}
	pw := make([]byte, 0, length)
	groups := []string{lowerChars, upperChars, digitChars, symbolChars}

	// Guarantee at least one of each
	for _, group := range groups {
		c, err := randomChar(group)
		if err != nil {
			return "", err
		}
		pw = append(pw, c)
	}
	// Fill rest
	for i := len(groups); i < length; i++ {
		c, err := randomChar(allChars)
		if err != nil {
			return "", err
		}
		pw = append(pw, c)
	}
	// Shuffle
	if err := shuffle(pw); err != nil {
		return "", err
	}
	return string(pw), nil
}

// GenerateURLSafePassword generates a cryptographically secure password
// using ONLY alphanumeric characters [a-zA-Z0-9].
//
// Why alphanumeric-only is BETTER than special characters for service credentials:
// 1. No escaping needed in ANY context (URLs, shells, SQL, YAML, TOML, JSON)
// 2. Maximum compatibility (works with legacy systems that reject special chars)
// 3. Length compensates for character set reduction - security is equivalent
// 4. Eliminates entire classes of bugs related to special character handling
//
// Character set: [a-zA-Z0-9] (62 possible characters)
// Entropy: log2(62^32) ≈ 190 bits for 32-character password (exceeds AES-128)
//
// Use this for:
//   - Database passwords in connection strings (DATABASE_URL)
//   - API keys and tokens
//   - Service-to-service authentication
//   - Any password that appears in config files, URLs, or shell commands
//   - Passwords passed through multiple systems/parsers
//
// DO NOT use for human user passwords - use GeneratePassword() instead
// (human passwords benefit from special characters for complexity requirements)
func GenerateURLSafePassword(length int) (string, error) {
	if length < MinPasswordLen {
		return "", errors.New("password too short: min length " + fmt.Sprintf("%d", MinPasswordLen))
	}

	password := make([]byte, length)
	for i := 0; i < length; i++ {
		c, err := randomChar(alphanumericChars)
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		password[i] = c
	}

	return string(password), nil
}

// ValidateStrongPassword checks that the password meets security policy.
func ValidateStrongPassword(_ctx context.Context, input string) error {
	if len(input) < MinPasswordLen {
		return errors.New("password too short")
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range input {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
		return errors.New("password missing required character class")
	}
	return nil
}

// randomChar selects a random character from charset using crypto/rand.
func randomChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

// shuffle randomizes a byte slice in place.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(jBig.Int64())
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

// ReadPassword reads a password from a bufio.Reader (e.g., for tests or non-interactive use).
func ReadPassword(reader *bufio.Reader) (string, error) {
	pw, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(pw), nil
}
