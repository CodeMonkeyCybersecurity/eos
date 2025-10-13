/* pkg/crypto/bcrypt.go */

package crypto

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ----------------------------
//  Hashing
// ----------------------------

func ConfirmHashedInputs(rc *eos_io.RuntimeContext, reader *bufio.Reader, keyLabel string, count int, tokenLabel string, expectedHashes []string, expectedTokenHash string) error {
	logger := otelzap.Ctx(rc.Ctx)

	for {
		logger.Info("terminal prompt: Please re-enter unique keys and token to confirm",
			zap.Int("key_count", count))

		keys, err := interaction.ReadLines(rc, reader, keyLabel, count)
		if err != nil {
			logger.Warn("Error reading keys", zap.Error(err))
			continue
		}

		token, err := interaction.ReadLine(rc.Ctx, reader, tokenLabel)
		if err != nil {
			logger.Warn("Error reading token", zap.Error(err))
			continue
		}

		if !AllUnique(keys) {
			logger.Warn("Keys must be unique, try again")
			continue
		}

		if !AllHashesPresent(HashStrings(keys), expectedHashes) || HashString(token) != expectedTokenHash {
			logger.Warn("One or more values are incorrect, try again")
			continue
		}

		logger.Info("Confirmation successful")
		return nil
	}
}

// HashString returns the SHA256 hash of a string as hex.
func HashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// HashFile returns the SHA256 hash of a file as hex.
func HashFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// HashStrings returns SHA256 hashes of each string in the input slice.
func HashStrings(inputs []string) []string {
	out := make([]string, len(inputs))
	for i, s := range inputs {
		out[i] = HashString(s)
	}
	return out
}

// AllUnique reports whether all strings in the slice are unique.
func AllUnique(items []string) bool {
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
func AllHashesPresent(hashes, known []string) bool {
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
//  Injecting secrets
// ----------------------------

// InjectSecretsFromPlaceholders replaces "changeme" and "changeme[1-9]" with passwords.
func InjectSecretsFromPlaceholders(data []byte) ([]byte, map[string]string, error) {
	content := string(data)
	replacements := make(map[string]string)

	// Process longer placeholders first to avoid substring replacement issues
	// Process changeme9 down to changeme1, then changeme
	for i := 9; i >= 0; i-- {
		placeholder := "changeme"
		if i > 0 {
			placeholder = fmt.Sprintf("changeme%d", i)
		}

		// Only generate password if placeholder exists in content
		if !strings.Contains(content, placeholder) {
			continue
		}

		pw, err := GeneratePassword(20)
		if err != nil {
			return nil, nil, fmt.Errorf("generate password for %s: %w", placeholder, err)
		}

		content = strings.ReplaceAll(content, placeholder, pw)
		replacements[placeholder] = pw
		fmt.Printf(" Secret injected: %s = %s\n", placeholder, pw)
	}

	return []byte(content), replacements, nil
}

// SecureZero overwrites a byte slice to reduce the chance of sensitive data lingering in memory.
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
