// Package crypto provides infrastructure implementations for cryptographic operations
package crypto

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/crypto"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// HashOperationsImpl implements crypto.HashOperations
type HashOperationsImpl struct {
	logger *zap.Logger
}

// NewHashOperations creates a new hash operations implementation
func NewHashOperations(logger *zap.Logger) *HashOperationsImpl {
	return &HashOperationsImpl{
		logger: logger,
	}
}

// HashString creates a hash of a string using the specified algorithm
func (h *HashOperationsImpl) HashString(ctx context.Context, input string, algorithm string) (string, error) {
	hash, err := h.HashBytes(ctx, []byte(input), algorithm)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash), nil
}

// HashBytes creates a hash of bytes using the specified algorithm
func (h *HashOperationsImpl) HashBytes(ctx context.Context, input []byte, algorithm string) ([]byte, error) {
	var hasher hash.Hash

	switch algorithm {
	case "sha256":
		hasher = sha256.New()
	case "sha384":
		hasher = sha512.New384()
	case "sha512":
		hasher = sha512.New()
	case "md5":
		// MD5 is cryptographically broken and should not be used for security purposes
		h.logger.Warn("MD5 hash algorithm is deprecated and insecure",
			zap.String("algorithm", algorithm),
			zap.String("recommendation", "use SHA-256 or higher"))
		hasher = md5.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	hasher.Write(input)
	result := hasher.Sum(nil)

	h.logger.Debug("Hash computed",
		zap.String("algorithm", algorithm),
		zap.Int("input_size", len(input)),
		zap.Int("output_size", len(result)),
	)

	return result, nil
}

// HashFile creates a hash of a file's contents
func (h *HashOperationsImpl) HashFile(ctx context.Context, path string, algorithm string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			h.logger.Error("failed to close file", zap.String("path", path), zap.Error(cerr))
		}
	}()

	var hasher hash.Hash
	switch algorithm {
	case "sha256":
		hasher = sha256.New()
	case "sha384":
		hasher = sha512.New384()
	case "sha512":
		hasher = sha512.New()
	case "md5":
		// MD5 is cryptographically broken and should not be used for security purposes
		h.logger.Warn("MD5 hash algorithm is deprecated and insecure",
			zap.String("algorithm", algorithm),
			zap.String("recommendation", "use SHA-256 or higher"))
		hasher = md5.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	result := fmt.Sprintf("%x", hasher.Sum(nil))

	h.logger.Debug("File hashed",
		zap.String("path", path),
		zap.String("algorithm", algorithm),
		zap.String("hash", result),
	)

	return result, nil
}

// VerifyHash verifies that a hash matches the expected value
func (h *HashOperationsImpl) VerifyHash(ctx context.Context, input []byte, expectedHash string, algorithm string) (bool, error) {
	actualHash, err := h.HashBytes(ctx, input, algorithm)
	if err != nil {
		return false, err
	}

	actual := fmt.Sprintf("%x", actualHash)
	match := actual == expectedHash

	h.logger.Debug("Hash verification",
		zap.String("algorithm", algorithm),
		zap.Bool("match", match),
	)

	return match, nil
}

// HashPassword creates a secure hash of a password (bcrypt)
func (h *HashOperationsImpl) HashPassword(ctx context.Context, password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	h.logger.Debug("Password hashed successfully")
	return string(hash), nil
}

// VerifyPassword verifies a password against its hash
func (h *HashOperationsImpl) VerifyPassword(ctx context.Context, password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, fmt.Errorf("failed to verify password: %w", err)
	}

	h.logger.Debug("Password verified successfully")
	return true, nil
}

// Ensure interface is implemented
var _ crypto.HashOperations = (*HashOperationsImpl)(nil)
