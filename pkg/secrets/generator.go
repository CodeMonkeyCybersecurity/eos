// Package secrets provides utilities for generating secure secrets
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
// It follows the Assess → Intervene → Evaluate pattern.
func Generate(opts *GenerateSecretOptions) (string, error) {
	// ASSESS - Validate options
	if opts.Length <= 0 {
		return "", errors.New("length must be greater than 0")
	}

	if opts.Format != "hex" && opts.Format != "base64" {
		return "", errors.New("unsupported format: must be 'hex' or 'base64'")
	}

	// INTERVENE - Generate random bytes
	buf := make([]byte, opts.Length)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}

	// EVALUATE - Encode to requested format
	var result string
	switch opts.Format {
	case "hex":
		result = hex.EncodeToString(buf)
	case "base64":
		result = base64.StdEncoding.EncodeToString(buf)
	}

	return result, nil
}

// GenerateHex generates a hex-encoded secret of the specified length
func GenerateHex(length int) (string, error) {
	return Generate(&GenerateSecretOptions{
		Length: length,
		Format: "hex",
	})
}

// GenerateBase64 generates a base64-encoded secret of the specified length
func GenerateBase64(length int) (string, error) {
	return Generate(&GenerateSecretOptions{
		Length: length,
		Format: "base64",
	})
}
