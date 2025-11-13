package fileops

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// FileOperationType represents the type of file operation
type FileOperationType string

const (
	OpCreate FileOperationType = "create"
	OpCopy   FileOperationType = "copy"
	OpMove   FileOperationType = "move"
	OpDelete FileOperationType = "delete"
	OpMkdir  FileOperationType = "mkdir"
)

// FileOperation represents a file operation to be performed
type FileOperation struct {
	Type       FileOperationType `json:"type"`
	Source     string            `json:"source,omitempty"`
	Target     string            `json:"target"`
	Content    []byte            `json:"content,omitempty"`
	Data       []byte            `json:"data,omitempty"`
	Mode       os.FileMode       `json:"mode,omitempty"`
	Completed  bool              `json:"completed"`
	BackupPath string            `json:"backup_path,omitempty"`
}

// SafeFileOperations provides safe file operations with transactions and backups
type SafeFileOperations struct {
	fileOps *FileSystemOperations
	logger  *zap.Logger
	locks   sync.Map // map[string]*sync.Mutex for file locking
}

// NewSafeFileOperations creates a new safe file operations implementation
func NewSafeFileOperations(fileOps *FileSystemOperations, logger *zap.Logger) *SafeFileOperations {
	return &SafeFileOperations{
		fileOps: fileOps,
		logger:  logger.Named("safe"),
	}
}

// WithBackup performs an operation with automatic backup
func (s *SafeFileOperations) WithBackup(ctx context.Context, path string, operation func() error) (backupPath string, err error) {
	s.logger.Debug("Performing operation with backup",
		zap.String("path", path))

	// Check if file exists
	exists, err := s.fileOps.Exists(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to check file existence: %w", err)
	}

	// Create backup if file exists
	if exists {
		backupPath = fmt.Sprintf("%s.backup.%d", path, time.Now().Unix())

		// Copy to backup
		if err := s.fileOps.CopyFile(ctx, path, backupPath, 0644); err != nil {
			return "", fmt.Errorf("failed to create backup: %w", err)
		}

		s.logger.Info("Backup created",
			zap.String("original", path),
			zap.String("backup", backupPath))

		// If operation fails, attempt to restore
		defer func() {
			if err != nil {
				s.logger.Warn("Operation failed, attempting to restore from backup",
					zap.String("path", path),
					zap.Error(err))

				if restoreErr := s.fileOps.CopyFile(ctx, backupPath, path, 0644); restoreErr != nil {
					s.logger.Error("Failed to restore from backup",
						zap.String("path", path),
						zap.String("backup", backupPath),
						zap.Error(restoreErr))
				} else {
					s.logger.Info("Successfully restored from backup",
						zap.String("path", path))
				}
			}
		}()
	}

	// Perform the operation
	if err := operation(); err != nil {
		return backupPath, fmt.Errorf("operation failed: %w", err)
	}

	s.logger.Info("Operation completed successfully",
		zap.String("path", path),
		zap.Bool("had_backup", exists))

	return backupPath, nil
}

// WithTransaction performs file operations transactionally
func (s *SafeFileOperations) WithTransaction(ctx context.Context, operations []FileOperation) error {
	s.logger.Info("Starting file transaction",
		zap.Int("operations", len(operations)))

	// Track completed operations for rollback
	completed := make([]FileOperation, 0, len(operations))

	// Rollback function
	rollback := func() {
		s.logger.Warn("Rolling back transaction",
			zap.Int("operations_to_rollback", len(completed)))

		// Reverse the completed operations
		for i := len(completed) - 1; i >= 0; i-- {
			op := completed[i]
			switch op.Type {
			case OpCreate:
				// Delete created file
				if err := s.fileOps.DeleteFile(ctx, op.Target); err != nil {
					s.logger.Error("Failed to rollback create",
						zap.String("file", op.Target),
						zap.Error(err))
				}
			case OpCopy:
				// Delete copied file
				if err := s.fileOps.DeleteFile(ctx, op.Target); err != nil {
					s.logger.Error("Failed to rollback copy",
						zap.String("file", op.Target),
						zap.Error(err))
				}
			case OpMove:
				// Move back
				if err := s.fileOps.MoveFile(ctx, op.Target, op.Source); err != nil {
					s.logger.Error("Failed to rollback move",
						zap.String("from", op.Target),
						zap.String("to", op.Source),
						zap.Error(err))
				}
			case OpDelete:
				// Can't rollback delete without backup
				s.logger.Warn("Cannot rollback delete operation",
					zap.String("file", op.Source))
			case OpMkdir:
				// Remove created directory
				if err := s.fileOps.DeleteFile(ctx, op.Target); err != nil {
					s.logger.Error("Failed to rollback mkdir",
						zap.String("dir", op.Target),
						zap.Error(err))
				}
			}
		}
	}

	// Execute operations
	for i, op := range operations {
		s.logger.Debug("Executing operation",
			zap.Int("index", i),
			zap.String("type", string(op.Type)),
			zap.String("target", op.Target))

		var err error
		switch op.Type {
		case OpCreate:
			err = s.fileOps.WriteFile(ctx, op.Target, op.Data, op.Mode)
		case OpCopy:
			err = s.fileOps.CopyFile(ctx, op.Source, op.Target, op.Mode)
		case OpMove:
			err = s.fileOps.MoveFile(ctx, op.Source, op.Target)
		case OpDelete:
			err = s.fileOps.DeleteFile(ctx, op.Source)
		case OpMkdir:
			err = s.fileOps.CreateDirectory(ctx, op.Target, op.Mode)
		default:
			err = fmt.Errorf("unknown operation type: %s", op.Type)
		}

		if err != nil {
			s.logger.Error("Operation failed",
				zap.Int("index", i),
				zap.String("type", string(op.Type)),
				zap.Error(err))

			// Rollback on error
			rollback()
			return fmt.Errorf("operation %d failed: %w", i, err)
		}

		// Track completed operation
		completed = append(completed, op)
	}

	s.logger.Info("Transaction completed successfully",
		zap.Int("operations", len(operations)))

	return nil
}

// WithLock performs an operation with file locking
func (s *SafeFileOperations) WithLock(ctx context.Context, path string, operation func() error) error {
	s.logger.Debug("Acquiring lock for file",
		zap.String("path", path))

	// Get or create mutex for this path
	lockInterface, _ := s.locks.LoadOrStore(path, &sync.Mutex{})
	lock := lockInterface.(*sync.Mutex)

	// Acquire lock
	lock.Lock()
	defer func() {
		lock.Unlock()
		s.logger.Debug("Released lock for file",
			zap.String("path", path))
	}()

	s.logger.Debug("Lock acquired for file",
		zap.String("path", path))

	// Perform operation
	return operation()
}
