// pkg/consul/service/atomic.go
// Atomic file operations for config updates

package service

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteConfigAtomic writes configuration atomically using temp file + rename
// This prevents corruption if process crashes mid-write
func WriteConfigAtomic(configPath string, content []byte) error {
	// Create temp file in same directory (required for atomic rename)
	dir := filepath.Dir(configPath)
	tempFile, err := os.CreateTemp(dir, ".consul-config-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	tempPath := tempFile.Name()

	// Ensure cleanup on failure
	defer func() {
		if tempFile != nil {
			tempFile.Close()
			os.Remove(tempPath)
		}
	}()

	// Write content to temp file
	if _, err := tempFile.Write(content); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}

	// Sync to disk
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp config: %w", err)
	}

	// Close before rename
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp config: %w", err)
	}

	// Set correct permissions
	if err := os.Chmod(tempPath, 0640); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename (only succeeds if on same filesystem)
	if err := os.Rename(tempPath, configPath); err != nil {
		return fmt.Errorf("failed to rename temp config to %s: %w", configPath, err)
	}

	// Success - prevent cleanup
	tempFile = nil

	return nil
}
