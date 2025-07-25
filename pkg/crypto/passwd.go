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
