// pkg/vault/errors.go
package vault

import (
	"errors"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
)

// IsSecretNotFound checks if a Vault error is a "404 not found" style error.
func IsSecretNotFound(err error) bool {
	if err == nil {
		return false
	}
	// Vault often wraps 404 errors with strings like "no secret found at path" or HTTP 404 error text.
	msg := err.Error()
	return strings.Contains(msg, "no secret") ||
		strings.Contains(msg, "404") ||
		errors.Is(err, eos_err.ErrSecretNotFound)
}
