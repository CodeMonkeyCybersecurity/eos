/* pkg/system/lifecycle.go */

package system

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"go.uber.org/zap"
)

// RemoveWithLog deletes a file or directory if it exists, with descriptive logging.
func Rm(path, label string, log *zap.Logger) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		abs, _ := filepath.Abs(path)
		log.Warn("Path not found", zap.String("label", label), zap.String("path", abs))
		fmt.Printf("⚠️  %s not found: %s\n", label, abs)
		return nil
	}

	if err != nil {
		utils.FailIfPermissionDenied(log, "access "+label, path, err)
		log.Error("Error accessing path", zap.String("label", label), zap.String("path", path), zap.Error(err))
		fmt.Printf("❌ Error accessing %s (%s): %v\n", label, path, err)
		return err
	}

	if info.IsDir() {
		log.Info("Removing directory", zap.String("label", label), zap.String("path", path))
		fmt.Printf("🧹 Removing directory (%s): %s\n", label, path)
		err = os.RemoveAll(path)
	} else {
		log.Info("Removing file", zap.String("label", label), zap.String("path", path))
		fmt.Printf("🧹 Removing file (%s): %s\n", label, path)
		err = os.Remove(path)
	}

	if err != nil {
		utils.FailIfPermissionDenied(log, "remove "+label, path, err)
		log.Error("Failed to remove", zap.String("label", label), zap.String("path", path), zap.Error(err))
		fmt.Printf("❌ Failed to remove %s (%s): %v\n", label, path, err)
		return err
	}

	log.Info("Successfully removed", zap.String("label", label), zap.String("path", path))
	fmt.Printf("✅ %s removed: %s\n", label, path)
	return nil
}

/* CopyFile copies a file from src to dst while preserving file permissions. */
func CopyFile(src, dst string, log *zap.Logger) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Ensure that the source is a regular file.
	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := source.Close(); cerr != nil {
			log.Warn("Failed to close source file", zap.Error(cerr))
		}
	}()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := destination.Close(); cerr != nil {
			log.Warn("Failed to close destination file", zap.Error(cerr))
		}
	}()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}

	// Copy the file permissions from source to destination.
	if err := os.Chmod(dst, sourceFileStat.Mode()); err != nil {
		return err
	}

	return nil
}

// CopyDir recursively copies a directory from src to dst.
func CopyDir(src, dst string, log *zap.Logger) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat src: %w", err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source is not a directory: %s", src)
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create dst dir: %w", err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read dir: %w", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := CopyDir(srcPath, dstPath, log); err != nil {
				return err
			}
		} else {
			if err := CopyFile(srcPath, dstPath, zap.L()); err != nil {
				return err
			}
		}
	}

	return nil
}
