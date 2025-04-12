// pkg/backup/backup.go
package backup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"go.uber.org/zap"
)

var log = logger.L()

// RestoreFile copies a single file from src to dst.
func RestoreFile(src, dst string) {
	log.Info("Restoring file", zap.String("source", src), zap.String("destination", dst))

	if err := utils.CopyFile(src, dst); err != nil {
		log.Error("Failed to restore file", zap.Error(err))
	} else {
		log.Info("File restored successfully", zap.String("destination", dst))
	}
}

// RestoreDir copies a full directory from src to dst.
func RestoreDir(src, dst string) {
	log.Info("Restoring directory", zap.String("source", src), zap.String("destination", dst))

	if err := system.Rm(dst, "destination directory"); err != nil {
		log.Error("Failed to clean destination", zap.String("destination", dst), zap.Error(err))
		return
	}
	if err := utils.CopyDir(src, dst); err != nil {
		log.Error("Failed to restore directory", zap.String("source", src), zap.Error(err))
	} else {
		log.Info("Directory restored successfully", zap.String("destination", dst))
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
