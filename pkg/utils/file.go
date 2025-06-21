// pkg/utils/file.go
// DEPRECATED: File operations should use pkg/eos_unix/filesystem.go instead

package utils

import (
	"context"
	"fmt"
	"os"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//
//---------------------------- FILE COMMANDS ---------------------------- //
//

// BackupFile makes a simple timestamped backup of the original file.
// DEPRECATED: Use pkg/eos_unix/filesystem.go for file operations
func BackupFile(ctx context.Context, path string) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("📄 Creating file backup", zap.String("path", path))

	backupPath := path + ".bak"
	input, err := os.ReadFile(path)
	if err != nil {
		logger.Error("❌ Failed to read file for backup",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to read file for backup: %w", err)
	}

	if err := os.WriteFile(backupPath, input, 0644); err != nil {
		logger.Error("❌ Failed to write backup file",
			zap.String("backup_path", backupPath),
			zap.Error(err))
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	logger.Info("✅ File backup created",
		zap.String("original", path),
		zap.String("backup", backupPath),
		zap.Int("size", len(input)))
	return nil
}

// CatFile outputs the content of a file to stderr with structured logging
// DEPRECATED: Use structured logging or pkg/eos_unix/filesystem.go for file operations
func CatFile(ctx context.Context, path string) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("📖 Reading file content", zap.String("path", path))

	data, err := os.ReadFile(path)
	if err != nil {
		logger.Error("❌ Failed to read file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Use stderr to preserve stdout for automation
	_, err = fmt.Fprint(os.Stderr, string(data))
	if err != nil {
		logger.Error("❌ Failed to output file content", zap.Error(err))
		return fmt.Errorf("failed to output file content: %w", err)
	}

	logger.Info("✅ File content displayed",
		zap.String("path", path),
		zap.Int("size", len(data)))
	return nil
}

// Backward compatibility functions

// BackupFileCompat provides backward compatibility
// DEPRECATED: Use BackupFile with context
func BackupFileCompat(path string) error {
	return BackupFile(context.Background(), path)
}

// CatFileCompat provides backward compatibility
// DEPRECATED: Use CatFile with context
func CatFileCompat(path string) error {
	return CatFile(context.Background(), path)
}
