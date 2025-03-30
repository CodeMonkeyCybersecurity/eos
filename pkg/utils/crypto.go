// pkg/utils/crypto.go

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

//
//---------------------------- CRYPTO, HASHING, SECRETS ---------------------------- //
//

// HashString computes and returns the SHA256 hash of the provided string.
func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	hashStr := hex.EncodeToString(hash[:])
	return hashStr
}

// generatePassword creates a random alphanumeric password of the given length.
func GeneratePassword(length int) (string, error) {
	// Generate random bytes. Since hex encoding doubles the length, we need length/2 bytes.
	bytes := make([]byte, length/2)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	// Encode to hex and trim to required length.
	return hex.EncodeToString(bytes)[:length], nil
}

// InjectSecretsFromPlaceholders scans the file content for "changeme", "changeme1", ..., "changeme9"
// and replaces each with a unique generated password. It returns the updated content and the replacements map.
func InjectSecretsFromPlaceholders(data []byte) ([]byte, map[string]string, error) {
	newData := string(data)
	replacements := map[string]string{}

	for i := 0; i < 10; i++ {
		var placeholder string
		if i == 0 {
			placeholder = "changeme"
		} else {
			placeholder = fmt.Sprintf("changeme%d", i)
		}

		password, err := GeneratePassword(20)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate password for placeholder %s: %w", placeholder, err)
		}

		newData = strings.ReplaceAll(newData, placeholder, password)
		replacements[placeholder] = password
		fmt.Printf("🔐 Secret injected: %s = %s\n", placeholder, password)
	}

	return []byte(newData), replacements, nil
}