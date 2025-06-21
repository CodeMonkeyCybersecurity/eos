// Package crypto provides key management infrastructure
package crypto

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/fileops"
	"go.uber.org/zap"
)

// FileBasedKeyManagement implements crypto.KeyManagement using file system
type FileBasedKeyManagement struct {
	keyDir  string
	fileOps fileops.FileOperations
	pathOps fileops.PathOperations
	logger  *zap.Logger
}

// NewFileBasedKeyManagement creates a new file-based key management implementation
func NewFileBasedKeyManagement(
	keyDir string,
	fileOps fileops.FileOperations,
	pathOps fileops.PathOperations,
	logger *zap.Logger,
) *FileBasedKeyManagement {
	return &FileBasedKeyManagement{
		keyDir:  keyDir,
		fileOps: fileOps,
		pathOps: pathOps,
		logger:  logger,
	}
}

// StoreKey securely stores a cryptographic key
func (f *FileBasedKeyManagement) StoreKey(ctx context.Context, keyID string, key []byte) error {
	// Ensure key directory exists
	if err := f.fileOps.CreateDirectory(ctx, f.keyDir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Create key file path
	keyPath := f.pathOps.JoinPath(f.keyDir, keyID+".key")

	// Store key with restrictive permissions
	if err := f.fileOps.WriteFile(ctx, keyPath, key, 0600); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

	f.logger.Info("Key stored successfully",
		zap.String("key_id", keyID),
		zap.String("path", keyPath),
	)

	return nil
}

// RetrieveKey retrieves a stored cryptographic key
func (f *FileBasedKeyManagement) RetrieveKey(ctx context.Context, keyID string) ([]byte, error) {
	keyPath := f.pathOps.JoinPath(f.keyDir, keyID+".key")

	// Check if key exists
	exists, err := f.fileOps.Exists(ctx, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to check key existence: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Read key
	key, err := f.fileOps.ReadFile(ctx, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key: %w", err)
	}

	f.logger.Debug("Key retrieved successfully",
		zap.String("key_id", keyID),
	)

	return key, nil
}

// DeleteKey securely deletes a stored key
func (f *FileBasedKeyManagement) DeleteKey(ctx context.Context, keyID string) error {
	keyPath := f.pathOps.JoinPath(f.keyDir, keyID+".key")

	// Check if key exists
	exists, err := f.fileOps.Exists(ctx, keyPath)
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	// Read key to overwrite it
	key, err := f.fileOps.ReadFile(ctx, keyPath)
	if err == nil {
		// Overwrite with zeros before deletion
		for i := range key {
			key[i] = 0
		}
		_ = f.fileOps.WriteFile(ctx, keyPath, key, 0600)
	}

	// Delete file
	if err := f.fileOps.DeleteFile(ctx, keyPath); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	f.logger.Info("Key deleted successfully",
		zap.String("key_id", keyID),
	)

	return nil
}

// RotateKey rotates a cryptographic key
func (f *FileBasedKeyManagement) RotateKey(ctx context.Context, keyID string) ([]byte, error) {
	// Generate new key (simplified - would use proper key generation in real implementation)
	newKey := make([]byte, 32) // 256-bit key
	// In real implementation, would use crypto/rand

	// Backup old key if it exists
	oldKeyPath := f.pathOps.JoinPath(f.keyDir, keyID+".key")
	exists, err := f.fileOps.Exists(ctx, oldKeyPath)
	if err == nil && exists {
		backupPath := f.pathOps.JoinPath(f.keyDir, keyID+".key.old")
		_ = f.fileOps.CopyFile(ctx, oldKeyPath, backupPath, 0600)
	}

	// Store new key
	if err := f.StoreKey(ctx, keyID, newKey); err != nil {
		return nil, fmt.Errorf("failed to store rotated key: %w", err)
	}

	f.logger.Info("Key rotated successfully",
		zap.String("key_id", keyID),
	)

	return newKey, nil
}

// ListKeys lists all stored key IDs
func (f *FileBasedKeyManagement) ListKeys(ctx context.Context) ([]string, error) {
	// Check if key directory exists
	exists, err := f.fileOps.Exists(ctx, f.keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to check key directory: %w", err)
	}
	if !exists {
		return []string{}, nil
	}

	// List directory contents
	entries, err := f.fileOps.ListDirectory(ctx, f.keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list key directory: %w", err)
	}

	var keyIDs []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".key" {
			// Remove .key extension to get key ID
			keyID := entry.Name()[:len(entry.Name())-4]
			keyIDs = append(keyIDs, keyID)
		}
	}

	f.logger.Debug("Keys listed",
		zap.Int("count", len(keyIDs)),
	)

	return keyIDs, nil
}

// Ensure interface is implemented
var _ crypto.KeyManagement = (*FileBasedKeyManagement)(nil)
