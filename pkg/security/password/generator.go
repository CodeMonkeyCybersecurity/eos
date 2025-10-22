package password

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
)

// GenerateSecure creates a cryptographically secure alphanumeric password
// Migrated from cmd/create/user.go generateSecurePassword
// REFACTORED: Now uses alphanumeric-only for maximum compatibility
func GenerateSecure() (string, error) {
	// ASSESS - Determine password requirements
	// Using 32 characters for strong security (log2(62^32) ≈ 190 bits)

	// INTERVENE - Generate alphanumeric-only password using crypto package
	// Alphanumeric-only prevents issues with special chars in shells, URLs, config files
	password, err := crypto.GenerateURLSafePassword(32)
	if err != nil {
		return "", err
	}

	// EVALUATE - Ensure password meets requirements
	// The crypto.GenerateURLSafePassword already ensures proper length and entropy

	return password, nil
}
