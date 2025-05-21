/* pkg/system/backup.go */

package debian

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// RestoreFile copies a single file from src to dst.
func RestoreFile(src, dst string) {
	zap.L().Info("Restoring file", zap.String("source", src), zap.String("destination", dst))

	if err := CopyFile(src, dst, 0); err != nil {
		zap.L().Error("Failed to restore file", zap.Error(err))
	} else {
		zap.L().Info("File restored successfully", zap.String("destination", dst))
	}
}

// RestoreDir copies a full directory from src to dst.
func RestoreDir(src, dst string) {
	stdCtx := context.Background()

	zap.L().Info("Restoring directory", zap.String("source", src), zap.String("destination", dst))

	if err := Rm(stdCtx, dst, "destination directory"); err != nil {
		zap.L().Error("Failed to clean destination", zap.String("destination", dst), zap.Error(err))
		return
	}
	if err := CopyDir(src, dst); err != nil {
		zap.L().Error("Failed to restore directory", zap.String("source", src), zap.Error(err))
	} else {
		zap.L().Info("Directory restored successfully", zap.String("destination", dst))
	}
}

// FindLatestBackup looks in the current directory for the newest file matching a prefix.
func FindLatestBackup(prefix string) (string, error) {
	files, err := filepath.Glob(fmt.Sprintf("%s*", prefix))
	if err != nil || len(files) == 0 {
		return "", fmt.Errorf("no backup files found with prefix '%s'", prefix)
	}

	// Find the most recently modified
	latest := files[0]
	info, _ := os.Stat(latest)
	for _, f := range files[1:] {
		fi, _ := os.Stat(f)
		if fi.ModTime().After(info.ModTime()) {
			latest = f
			info = fi
		}
	}

	return latest, nil
}
