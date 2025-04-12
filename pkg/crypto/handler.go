/* pkg/crypto/handler.go */

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// ----------------------------
// 🔐 Hashing
// ----------------------------

// HashString returns the SHA256 hash of a string as hex.
func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// HashStrings returns SHA256 hashes of each string in the input slice.
func hashStrings(inputs []string) []string {
	out := make([]string, len(inputs))
	for i, s := range inputs {
		out[i] = hashString(s)
	}
	return out
}

// AllUnique reports whether all strings in the slice are unique.
func allUnique(items []string) bool {
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if _, exists := seen[item]; exists {
			return false
		}
		seen[item] = struct{}{}
	}
	return true
}

// AllHashesPresent checks that each hash in `hashes` exists in `known`.
func allHashesPresent(hashes, known []string) bool {
	for _, h := range hashes {
		found := false
		for _, k := range known {
			if h == k {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ----------------------------
// 🔐 Passwords
// ----------------------------

// GeneratePassword creates a strong random password with at least 1 of each char class.
func generatePassword(length int) (string, error) {
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

// ----------------------------
// 🔐 Injecting secrets
// ----------------------------

// InjectSecretsFromPlaceholders replaces "changeme" and "changeme[1-9]" with passwords.
func injectSecretsFromPlaceholders(data []byte) ([]byte, map[string]string, error) {
	content := string(data)
	replacements := make(map[string]string)

	for i := 0; i < 10; i++ {
		placeholder := "changeme"
		if i > 0 {
			placeholder = fmt.Sprintf("changeme%d", i)
		}

		pw, err := generatePassword(20)
		if err != nil {
			return nil, nil, fmt.Errorf("generate password for %s: %w", placeholder, err)
		}

		content = strings.ReplaceAll(content, placeholder, pw)
		replacements[placeholder] = pw
		fmt.Printf("🔐 Secret injected: %s = %s\n", placeholder, pw)
	}

	return []byte(content), replacements, nil
}

func Redact(s string) string {
	if s == "" {
		return "(empty)"
	}
	return strings.Repeat("*", 8)
}
