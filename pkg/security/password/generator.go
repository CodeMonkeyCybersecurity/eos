package password

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
)

// GenerateSecure creates a cryptographically secure password
// Migrated from cmd/create/user.go generateSecurePassword
func GenerateSecure() (string, error) {
	// ASSESS - Determine password requirements
	// Using 16 characters as default length for strong security

	// INTERVENE - Generate password using crypto package
	password, err := crypto.GeneratePassword(16)
	if err != nil {
		return "", err
	}

	// EVALUATE - Ensure password meets requirements
	// The crypto.GeneratePassword already ensures proper complexity

	return password, nil
}
