// Package secrets provides utilities for generating secure secrets
//
// DEPRECATED: This file is deprecated. Use pkg/crypto for all secret generation.
// - crypto.GenerateHex(byteLength) - Hex-encoded secrets
// - crypto.GenerateBase64(byteLength) - Base64-encoded secrets
// - crypto.GenerateAPIKey(length) - Alphanumeric API keys
// - crypto.GenerateToken(length) - Alphanumeric tokens
// - crypto.GenerateURLSafePassword(length) - Alphanumeric passwords
//
// The functions below are kept for backward compatibility but will be removed in a future version.
// All new code should use pkg/crypto directly.
package secrets

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
)

// GenerateSecretOptions contains options for secret generation
type GenerateSecretOptions struct {
	Length int
	Format string
}

// DefaultOptions returns default secret generation options
func DefaultOptions() *GenerateSecretOptions {
	return &GenerateSecretOptions{
		Length: 32,
		Format: "hex",
	}
}

// Generate creates a secure random secret with the specified options.
// DEPRECATED: Use crypto.GenerateHex() or crypto.GenerateBase64() instead.
func Generate(opts *GenerateSecretOptions) (string, error) {
	// Delegate to crypto package
	switch opts.Format {
	case "hex":
		return crypto.GenerateHex(opts.Length)
	case "base64":
		return crypto.GenerateBase64(opts.Length)
	default:
		return crypto.GenerateHex(opts.Length) // Default to hex
	}
}

// GenerateHex generates a hex-encoded secret of the specified length
// DEPRECATED: Use crypto.GenerateHex() instead.
func GenerateHex(length int) (string, error) {
	return crypto.GenerateHex(length)
}

// GenerateBase64 generates a base64-encoded secret of the specified length
// DEPRECATED: Use crypto.GenerateBase64() instead.
func GenerateBase64(length int) (string, error) {
	return crypto.GenerateBase64(length)
}
