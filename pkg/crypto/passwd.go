package crypto

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"unicode"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// GeneratePassword creates a strong random password with at least 1 of each char class.
func GeneratePassword(length int) (string, error) {
	if length < 4 {
		return "", errors.New(shared.ErrPasswordTooShort)
	}

	var pw []byte

	for _, group := range []string{shared.LowerChars, shared.UpperChars, shared.DigitChars, shared.SymbolChars} {
		c, err := randomChar(group)
		if err != nil {
			return "", fmt.Errorf("failed to select random char: %w", err)
		}
		pw = append(pw, c)
	}

	for i := len(pw); i < length; i++ {
		c, err := randomChar(shared.AllChars)
		if err != nil {
			return "", fmt.Errorf("failed to select random filler char: %w", err)
		}
		pw = append(pw, c)
	}

	if err := shuffle(pw); err != nil {
		return "", fmt.Errorf("failed to shuffle password: %w", err)
	}

	return string(pw), nil
}

func TestGeneratePassword(t *testing.T) {
	pw, err := GeneratePassword(16)
	if err != nil {
		t.Fatalf("GeneratePassword failed: %v", err)
	}
	if len(pw) < 16 {
		t.Errorf("password too short: got %d, want >=16", len(pw))
	}
}

func TestValidateStrongPassword(t *testing.T) {
	log := zap.NewNop() // No-op logger for tests

	valid := "Astrong!Pass123"
	if err := ValidateStrongPassword(valid, log); err != nil {
		t.Errorf("ValidateStrongPassword rejected valid password: %v", err)
	}

	invalid := "weakpass"
	if err := ValidateStrongPassword(invalid, log); err == nil {
		t.Error("ValidateStrongPassword accepted weak password, expected error")
	}
}

func TestReadPassword(t *testing.T) {
	input := "testpassword\n"
	reader := bufio.NewReader(strings.NewReader(input))
	pw, err := ReadPassword(reader)
	if err != nil {
		t.Fatalf("ReadPassword failed: %v", err)
	}
	if pw != "testpassword" {
		t.Errorf("ReadPassword incorrect: got %q, want %q", pw, "testpassword")
	}
}

// randomChar selects a random character from a charset using crypto-randomness.
func randomChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random index: %w", err)
	}
	return charset[n.Int64()], nil
}

// shuffle randomizes a byte slice in place using crypto-random swaps.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("failed to generate random shuffle index: %w", err)
		}
		j := int(jBig.Int64())
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

// ValidateStrongPassword ensures min length and mixed char types.

func ValidateStrongPassword(input string, log *zap.Logger) error {
	if len(input) < 12 {
		log.Warn("password too short", zap.Int("length", len(input)))
		return errors.New(shared.ErrPasswordTooShort)
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
		log.Warn("password missing required character classes")
		return errors.New(shared.ErrPasswordMissingClasses)
	}

	return nil
}

// ReadPassword reads a password securely from a buffered reader.
func ReadPassword(reader *bufio.Reader) (string, error) {
	pw, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return strings.TrimSpace(pw), nil
}
