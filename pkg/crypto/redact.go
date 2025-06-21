// pkg/crypto/redact.go

package crypto

import "strings"

// Redact returns a string of asterisks of the same length as the input.
// Use for masking secrets in logs (not cryptographically secure).
func Redact(s string) string {
	if s == "" {
		return "(empty)"
	}
	return strings.Repeat("*", len([]rune(s)))
}
