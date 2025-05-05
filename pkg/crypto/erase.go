// pkg/crypto/erase.go

package crypto

import (
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

// SecureErase securely deletes a file (best effort).
func SecureErase(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	if err := execute.Execute("shred", "--remove", "--zero", "--iterations=3", path); err != nil {
		// fallback: just remove if shred is missing
		return os.Remove(path)
	}
	return nil
}
