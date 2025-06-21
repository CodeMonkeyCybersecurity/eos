/* pkg/crypto/bcrypt.go */

package crypto

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

// ----------------------------
// 🔐 Hashing
// ----------------------------

func ConfirmHashedInputs(rc *eos_io.RuntimeContext, reader *bufio.Reader, keyLabel string, count int, tokenLabel string, expectedHashes []string, expectedTokenHash string) error {
	for {
		fmt.Printf("Please re-enter %d unique keys and the token to confirm.\n", count)

		keys, err := interaction.ReadLines(rc, reader, keyLabel, count)
		if err != nil {
			fmt.Println("❌ Error reading keys:", err)
			continue
		}

		token, err := interaction.ReadLine(rc.Ctx, reader, tokenLabel)
		if err != nil {
			fmt.Println("❌ Error reading token:", err)
			continue
		}

		if !AllUnique(keys) {
			fmt.Println("⚠️ Keys must be unique. Try again.")
			continue
		}

		if !AllHashesPresent(HashStrings(keys), expectedHashes) || HashString(token) != expectedTokenHash {
			fmt.Println("❌ One or more values are incorrect. Try again.")
			continue
		}

		fmt.Println("✅ Confirmation successful.")
		return nil
	}
}

// HashString returns the SHA256 hash of a string as hex.
func HashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
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
// 🔐 Injecting secrets
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
		fmt.Printf("🔐 Secret injected: %s = %s\n", placeholder, pw)
	}

	return []byte(content), replacements, nil
}

// SecureZero overwrites a byte slice to reduce the chance of sensitive data lingering in memory.
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
