// pkg/crypto/passwd.go

package crypto

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"unicode"

	"go.uber.org/zap"
)

// GeneratePassword creates a strong random password with at least 1 of each char class.
func GeneratePassword(length int) (string, error) {
	if length < 4 {
		return "", fmt.Errorf("password length must be at least 4")
	}

	lower := "abcdefghijklmnopqrstuvwxyz"
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	symbols := "!@#$%&*?" // bash-safe
	all := lower + upper + digits + symbols

	var pw []byte

	// Guarantee 1 character from each category
	for _, group := range []string{lower, upper, digits, symbols} {
		c, err := randomChar(group)
		if err != nil {
			return "", err
		}
		pw = append(pw, c)
	}

	// Fill the rest
	for i := len(pw); i < length; i++ {
		c, err := randomChar(all)
		if err != nil {
			return "", err
		}
		pw = append(pw, c)
	}

	if err := shuffle(pw); err != nil {
		return "", err
	}

	return string(pw), nil
}

func randomChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

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

// ValidateStrongPassword ensures min length and mixed char types.
func ValidateStrongPassword(input string, log *zap.Logger) error {
	if len(input) < 12 {
		return errors.New("password must be at least 12 characters long")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false

	for _, r := range input {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
		return errors.New("password must include upper/lower case letters, numbers, and symbols")
	}

	return nil
}

/**/
// crypto.ReadPassword
func ReadPassword(reader *bufio.Reader) (string, error) {
	pw, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return string(pw[:len(pw)-1]), nil
}
