/* pkg/unix/backup.go */

package eos_unix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// Restore does a “rm -rf dst && cp -r src dst“ under one roof.
func Restore(ctx context.Context, src, dst string) error {
	log := zap.L().With(
		zap.String("source", src),
		zap.String("destination", dst),
	)
	log.Info("Restoring path")

	// Clean destination
	if err := RmRF(ctx, dst, "restored path"); err != nil {
		log.Error("Failed to clean destination", zap.Error(err))
		return fmt.Errorf("cleanup %q: %w", dst, err)
	}

	// Decide file vs. dir
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat %q: %w", src, err)
	}

	if info.IsDir() {
		if err := CopyR(ctx, src, dst); err != nil {
			log.Error("Failed to copy directory", zap.Error(err))
			return fmt.Errorf("copy dir %q→%q: %w", src, dst, err)
		}
	} else {
		// default to a sensible mode
		if err := CopyFile(ctx, src, dst, 0o600); err != nil {
			log.Error("Failed to copy file", zap.Error(err))
			return fmt.Errorf("copy file %q→%q: %w", src, dst, err)
		}
	}

	log.Info("Restore completed")
	return nil
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
