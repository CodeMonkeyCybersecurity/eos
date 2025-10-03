// Package crypto provides encryption operations infrastructure
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"go.uber.org/zap"
	"golang.org/x/crypto/pbkdf2"
)

// EncryptionOperationsImpl provides crypto operations
type EncryptionOperationsImpl struct {
	logger *zap.Logger
}

// NewEncryptionOperations creates a new encryption operations implementation
func NewEncryptionOperations(logger *zap.Logger) *EncryptionOperationsImpl {
	return &EncryptionOperationsImpl{
		logger: logger,
	}
}

// Encrypt encrypts data using AES-GCM
func (e *EncryptionOperationsImpl) Encrypt(ctx context.Context, plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	e.logger.Debug("Data encrypted",
		zap.Int("plaintext_size", len(plaintext)),
		zap.Int("ciphertext_size", len(ciphertext)),
	)

	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM
func (e *EncryptionOperationsImpl) Decrypt(ctx context.Context, ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	e.logger.Debug("Data decrypted",
		zap.Int("ciphertext_size", len(ciphertext)+nonceSize),
		zap.Int("plaintext_size", len(plaintext)),
	)

	return plaintext, nil
}

// EncryptStream encrypts data from a reader to a writer
// SECURITY: Enforces maximum size limit to prevent DoS via memory exhaustion
func (e *EncryptionOperationsImpl) EncryptStream(ctx context.Context, reader io.Reader, writer io.Writer, key []byte) error {
	// CRITICAL: Limit input size to prevent DoS attack via unbounded memory allocation
	// Attacker could send 100GB stream causing OOM crash
	const maxStreamSize = 100 * 1024 * 1024 // 100MB maximum

	limitedReader := io.LimitReader(reader, maxStreamSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	// Check if we hit the limit (data is exactly maxStreamSize means there's more)
	if int64(len(data)) == maxStreamSize {
		// Try to read one more byte to confirm
		oneByte := make([]byte, 1)
		n, _ := reader.Read(oneByte)
		if n > 0 {
			return fmt.Errorf("input stream exceeds maximum size of %d bytes", maxStreamSize)
		}
	}

	encrypted, err := e.Encrypt(ctx, data, key)
	if err != nil {
		return err
	}

	_, err = writer.Write(encrypted)
	if err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	return nil
}

// DecryptStream decrypts data from a reader to a writer
// SECURITY: Enforces maximum size limit to prevent DoS via memory exhaustion
func (e *EncryptionOperationsImpl) DecryptStream(ctx context.Context, reader io.Reader, writer io.Writer, key []byte) error {
	// CRITICAL: Limit input size to prevent DoS attack
	const maxStreamSize = 100 * 1024 * 1024 // 100MB maximum

	limitedReader := io.LimitReader(reader, maxStreamSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	// Check if we hit the limit
	if int64(len(data)) == maxStreamSize {
		oneByte := make([]byte, 1)
		n, _ := reader.Read(oneByte)
		if n > 0 {
			return fmt.Errorf("input stream exceeds maximum size of %d bytes", maxStreamSize)
		}
	}

	decrypted, err := e.Decrypt(ctx, data, key)
	if err != nil {
		return err
	}

	_, err = writer.Write(decrypted)
	if err != nil {
		return fmt.Errorf("failed to write decrypted data: %w", err)
	}

	return nil
}

// GenerateKey generates a new encryption key
func (e *EncryptionOperationsImpl) GenerateKey(ctx context.Context, bits int) ([]byte, error) {
	bytes := bits / 8
	key := make([]byte, bytes)

	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	e.logger.Debug("Encryption key generated",
		zap.Int("bits", bits),
		zap.Int("bytes", bytes),
	)

	return key, nil
}

// DeriveKey derives a key from a password using PBKDF2
// SECURITY: Uses 600,000 iterations (OWASP 2023 recommendation) with SHA-256
func (e *EncryptionOperationsImpl) DeriveKey(ctx context.Context, password string, salt []byte, keyLen int) ([]byte, error) {
	// Validate inputs
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes (got %d)", len(salt))
	}

	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, fmt.Errorf("invalid key length: %d (must be 16, 24, or 32 for AES)", keyLen)
	}

	// OWASP 2023 recommendation: 600,000 iterations for PBKDF2-SHA256
	// This provides strong protection against brute-force attacks
	// Iteration count from: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	const iterations = 600000

	// Derive key using PBKDF2 with SHA-256
	key := pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha256.New)

	e.logger.Debug("Key derived successfully",
		zap.Int("key_length", keyLen),
		zap.Int("salt_length", len(salt)),
		zap.Int("iterations", iterations))

	return key, nil
}
