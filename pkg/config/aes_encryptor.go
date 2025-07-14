// Package config provides infrastructure implementations for configuration management
package config

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"go.uber.org/zap"
)

// AESEncryptor implements Encryptor using AES encryption
type AESEncryptor struct {
	key    []byte
	logger *zap.Logger
}

// NewAESEncryptor creates a new AES encryptor
func NewAESEncryptor(key []byte, logger *zap.Logger) *AESEncryptor {
	return &AESEncryptor{
		key:    key,
		logger: logger.Named("config.aes_encryptor"),
	}
}

// Encrypt encrypts configuration data
func (e *AESEncryptor) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
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

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Encode to base64 for safe storage
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encoded, ciphertext)

	e.logger.Debug("Data encrypted successfully",
		zap.Int("plaintext_size", len(data)),
		zap.Int("ciphertext_size", len(encoded)))

	return encoded, nil
}

// Decrypt decrypts configuration data
func (e *AESEncryptor) Decrypt(ctx context.Context, data []byte) ([]byte, error) {
	// Decode from base64
	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(ciphertext, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	ciphertext = ciphertext[:n]

	block, err := aes.NewCipher(e.key)
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

	e.logger.Debug("Data decrypted successfully",
		zap.Int("ciphertext_size", len(data)),
		zap.Int("plaintext_size", len(plaintext)))

	return plaintext, nil
}

// IsEncrypted checks if data is encrypted
func (e *AESEncryptor) IsEncrypted(ctx context.Context, data []byte) bool {
	// Simple heuristic: try to decode as base64
	// Real encrypted data should be base64 encoded
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	_, err := base64.StdEncoding.Decode(decoded, data)

	// If it's valid base64 and looks like encrypted data, assume it's encrypted
	return err == nil && len(data) > 32 // Minimum size for AES-GCM
}

// EncryptField encrypts a specific field in the configuration
func (e *AESEncryptor) EncryptField(ctx context.Context, data map[string]interface{}, fieldPath string) error {
	value, exists := data[fieldPath]
	if !exists {
		return fmt.Errorf("field %s not found", fieldPath)
	}

	// Convert value to bytes
	valueBytes := []byte(fmt.Sprintf("%v", value))

	// Encrypt the value
	encrypted, err := e.Encrypt(ctx, valueBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt field %s: %w", fieldPath, err)
	}

	// Store the encrypted value
	data[fieldPath] = string(encrypted)

	e.logger.Debug("Field encrypted successfully",
		zap.String("field", fieldPath))

	return nil
}

// DecryptField decrypts a specific field in the configuration
func (e *AESEncryptor) DecryptField(ctx context.Context, data map[string]interface{}, fieldPath string) error {
	value, exists := data[fieldPath]
	if !exists {
		return fmt.Errorf("field %s not found", fieldPath)
	}

	valueStr, ok := value.(string)
	if !ok {
		return fmt.Errorf("field %s is not a string", fieldPath)
	}

	// Decrypt the value
	decrypted, err := e.Decrypt(ctx, []byte(valueStr))
	if err != nil {
		return fmt.Errorf("failed to decrypt field %s: %w", fieldPath, err)
	}

	// Store the decrypted value
	data[fieldPath] = string(decrypted)

	e.logger.Debug("Field decrypted successfully",
		zap.String("field", fieldPath))

	return nil
}
