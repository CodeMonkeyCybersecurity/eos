// pkg/crypto/password_encryption.go

package crypto

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EncryptWithPassword encrypts data using AES-256-GCM with a password-derived key
// SECURITY: Uses PBKDF2 with 600,000 iterations (OWASP 2023 recommendation)
func EncryptWithPassword(plaintext []byte, password string) ([]byte, error) {
	// Generate random salt (16 bytes minimum for PBKDF2)
	salt := make([]byte, 32) // Use 32 bytes for extra security
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Create encryption operations instance
	// Note: We're using a nil logger here for standalone function
	// If logging is needed, could accept RuntimeContext parameter
	encOps := NewEncryptionOperations(otelzap.L().Logger)

	// Derive key from password using PBKDF2
	// Uses 600,000 iterations with SHA-256 (OWASP 2023 recommendation)
	key, err := encOps.DeriveKey(context.TODO(), password, salt, 32) // 32 bytes = AES-256
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	// Encrypt plaintext with derived key
	ciphertext, err := encOps.Encrypt(context.TODO(), plaintext, key)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	// Prepend salt to ciphertext
	// Format: [32-byte salt][nonce + encrypted data]
	result := append(salt, ciphertext...)

	// Zero out key after use
	SecureZero(key)

	return result, nil
}

// DecryptWithPassword decrypts data that was encrypted with EncryptWithPassword
func DecryptWithPassword(encrypted []byte, password string) ([]byte, error) {
	// Extract salt from beginning of encrypted data
	if len(encrypted) < 32 {
		return nil, fmt.Errorf("encrypted data too short (minimum 32 bytes for salt)")
	}

	salt := encrypted[:32]
	ciphertext := encrypted[32:]

	// Create encryption operations instance
	encOps := NewEncryptionOperations(otelzap.L().Logger)

	// Derive key from password using same parameters as encryption
	key, err := encOps.DeriveKey(context.TODO(), password, salt, 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	// Decrypt ciphertext
	plaintext, err := encOps.Decrypt(context.TODO(), ciphertext, key)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	// Zero out key after use
	SecureZero(key)

	return plaintext, nil
}

// EncryptFileWithPassword encrypts a file with password-based encryption
func EncryptFileWithPassword(inputPath, outputPath, password string) error {
	// Read input file
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}

	// Encrypt data
	encrypted, err := EncryptWithPassword(plaintext, password)
	if err != nil {
		return fmt.Errorf("encrypt data: %w", err)
	}

	// Write encrypted data to output file
	if err := os.WriteFile(outputPath, encrypted, shared.SecretFilePerm); err != nil {
		return fmt.Errorf("write encrypted file: %w", err)
	}

	otelzap.L().Info("File encrypted successfully",
		zap.String("input", inputPath),
		zap.String("output", outputPath),
		zap.Int("original_size", len(plaintext)),
		zap.Int("encrypted_size", len(encrypted)))

	return nil
}

// DecryptFileWithPassword decrypts a file that was encrypted with EncryptFileWithPassword
func DecryptFileWithPassword(inputPath, outputPath, password string) error {
	// Read encrypted file
	encrypted, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read encrypted file: %w", err)
	}

	// Decrypt data
	plaintext, err := DecryptWithPassword(encrypted, password)
	if err != nil {
		return fmt.Errorf("decrypt data: %w", err)
	}

	// Write decrypted data to output file
	if err := os.WriteFile(outputPath, plaintext, shared.SecretFilePerm); err != nil {
		return fmt.Errorf("write decrypted file: %w", err)
	}

	otelzap.L().Info("File decrypted successfully",
		zap.String("input", inputPath),
		zap.String("output", outputPath),
		zap.Int("encrypted_size", len(encrypted)),
		zap.Int("decrypted_size", len(plaintext)))

	return nil
}
