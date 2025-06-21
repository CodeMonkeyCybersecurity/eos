// Package crypto provides random operations infrastructure
package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/crypto"
	"github.com/google/uuid"
)

// RandomOperationsImpl implements crypto.RandomOperations
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
		charset = crypto.CharsetAlphaNum
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

// GeneratePassword generates a secure random password
func (r *RandomOperationsImpl) GeneratePassword(ctx context.Context, length int, includeSpecial bool) (string, error) {
	charset := crypto.CharsetAlphaNum
	if includeSpecial {
		charset = crypto.CharsetAll
	}

	return r.GenerateRandomString(ctx, length, charset)
}

// Ensure interface is implemented
var _ crypto.RandomOperations = (*RandomOperationsImpl)(nil)
