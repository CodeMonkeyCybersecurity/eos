// Package crypto provides key management infrastructure
package crypto

import (
	"context"
	"fmt"
	"path/filepath"

	"go.uber.org/zap"
)

// FileOperations interface for file operations
type FileOperations interface {
	CreateDirectory(ctx context.Context, path string, mode int) error
	WriteFile(ctx context.Context, path string, data []byte, mode int) error
	ReadFile(ctx context.Context, path string) ([]byte, error)
	DeleteFile(ctx context.Context, path string) error
	FileExists(ctx context.Context, path string) (bool, error)
	Exists(ctx context.Context, path string) (bool, error)
	CopyFile(ctx context.Context, src, dst string, mode int) error
	ListDirectory(ctx context.Context, path string) ([]string, error)
}

// PathOperations interface for path operations
type PathOperations interface {
	JoinPath(elements ...string) string
}

// FileBasedKeyManagement provides file-based key management
type FileBasedKeyManagement struct {
	keyDir  string
	logger  *zap.Logger
	fileOps FileOperations
	pathOps PathOperations
}

// NewFileBasedKeyManagement creates a new file-based key management implementation
func NewFileBasedKeyManagement(keyDir string, logger *zap.Logger, fileOps FileOperations, pathOps PathOperations) *FileBasedKeyManagement {
	return &FileBasedKeyManagement{
		keyDir:  keyDir,
		logger:  logger,
		fileOps: fileOps,
		pathOps: pathOps,
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
	for _, filename := range entries {
		if filepath.Ext(filename) == ".key" {
			// Remove .key extension to get key ID
			keyID := filename[:len(filename)-4]
			keyIDs = append(keyIDs, keyID)
		}
	}

	f.logger.Debug("Keys listed",
		zap.Int("count", len(keyIDs)),
	)

	return keyIDs, nil
}
