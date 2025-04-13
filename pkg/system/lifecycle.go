/* pkg/system/lifecycle.go */

package system

import (
	"fmt"
	"io"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"go.uber.org/zap"
)

// RemoveWithLog deletes a file or directory if it exists, with descriptive logging.
func Rm(path, label string, log *zap.Logger) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		log.Warn("Path not found", zap.String("label", label), zap.String("path", path))
		fmt.Printf("⚠️  %s not found: %s\n", label, path)
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

/* copyFile copies a file from src to dst while preserving file permissions. */
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
