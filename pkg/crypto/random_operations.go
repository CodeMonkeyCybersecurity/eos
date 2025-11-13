// Package crypto provides random operations infrastructure
package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/google/uuid"
)

// RandomOperationsImpl provides crypto operations
type RandomOperationsImpl struct{}

// NewRandomOperations creates a new random operations implementation
func NewRandomOperations() *RandomOperationsImpl {
	return &RandomOperationsImpl{}
}

// GenerateRandomBytes generates cryptographically secure random bytes
func (r *RandomOperationsImpl) GenerateRandomBytes(ctx context.Context, length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// GenerateRandomString generates a random string with specified character set
func (r *RandomOperationsImpl) GenerateRandomString(ctx context.Context, length int, charset string) (string, error) {
	if len(charset) == 0 {
		charset = CharsetAlphaNum
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		result[i] = charset[index.Int64()]
	}

	return string(result), nil
}

// GenerateUUID generates a random UUID
func (r *RandomOperationsImpl) GenerateUUID(ctx context.Context) (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}
	return id.String(), nil
}

// GeneratePassword generates a secure random alphanumeric-only password
// REFACTORED: Now always uses alphanumeric-only [a-zA-Z0-9] for maximum compatibility
// The includeSpecial parameter is DEPRECATED and ignored (kept for backward compatibility)
func (r *RandomOperationsImpl) GeneratePassword(ctx context.Context, length int, includeSpecial bool) (string, error) {
	// Always use alphanumeric charset - special chars cause too many issues
	// (shell escaping, URL encoding, config file parsing, database connection strings, etc.)
	// The entropy loss is negligible: log2(62^32) ≈ 190 bits vs log2(94^32) ≈ 211 bits
	charset := CharsetAlphaNum

	return r.GenerateRandomString(ctx, length, charset)
}
