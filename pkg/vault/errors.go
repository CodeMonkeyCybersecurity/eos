// pkg/vault/errors.go
package vault

import (
	"errors"
	"strings"
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
		errors.Is(err, ErrSecretNotFound)
}

// Optional: you can predefine a standard error for special cases
var ErrSecretNotFound = errors.New("vault secret not found")
