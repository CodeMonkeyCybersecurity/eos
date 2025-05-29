// pkg/crypto/erase.go

package crypto

import (
	"context"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

// SecureErase securely deletes a file (best effort).
func SecureErase(ctx context.Context, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	if err := execute.RunSimple(ctx, "shred", "--remove", "--zero", "--iterations=3", path); err != nil {
		// fallback: just remove if shred is missing
		return os.Remove(path)
	}
	return nil
}
