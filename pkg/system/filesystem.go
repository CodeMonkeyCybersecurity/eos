// pkg/system/filesystem.go

package system

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// EnsureDir ensures that the given directory exists, creating it if needed.
func EnsureDir(path string) error {
	return ensureDirWithOwner(path, shared.DirPermStandard, "")
}

// EnsureOwnedDir ensures that the directory exists with the correct owner and permissions.
func EnsureOwnedDir(path string, perm os.FileMode, owner string) error {
	return ensureDirWithOwner(path, perm, owner)
}

// --- shared internal helper ---
func ensureDirWithOwner(path string, perm os.FileMode, owner string) error {
	log := zap.L().Named("system-filesystem")

	absPath, err := filepath.Abs(path)
	if err != nil {
		log.Error("Failed to resolve absolute path", zap.Error(err), zap.String("input_path", path))
		return err
	}

	info, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		log.Info("Directory does not exist, creating...", zap.String("path", absPath))
		if err := os.MkdirAll(absPath, perm); err != nil {
			log.Error("Failed to create directory", zap.Error(err), zap.String("path", absPath))
			return err
		}
		log.Info("✅ Directory created", zap.String("path", absPath))
	} else if err != nil {
		log.Error("Error checking directory", zap.Error(err), zap.String("path", absPath))
		return err
	} else if !info.IsDir() {
		log.Error("Path exists but is not a directory", zap.String("path", absPath))
		return os.ErrInvalid
	} else {
		log.Info("Directory already exists", zap.String("path", absPath))
	}

	if owner != "" {
		if err := EnsureOwnership(absPath, owner); err != nil {
			return fmt.Errorf("ownership adjustment failed: %w", err)
		}
	}

	return nil
}

// EnsureDirs ensures that a list of directories exist (mkdir -p style).
func EnsureDirs(paths []string) error {
	log := zap.L().Named("system-filesystem")
	for _, path := range paths {
		log.Info("Ensuring directory exists", zap.String("path", path))
		if err := EnsureDir(path); err != nil {
			return fmt.Errorf("failed to ensure directory %s: %w", path, err)
		}
	}
	return nil
}

// EnsureOwnership sets the ownership of a file or directory to the given user.
func EnsureOwnership(path string, owner string) error {
	log := zap.L().Named("system-filesystem")
	uid, gid, err := LookupUser(owner)
	if err != nil {
		log.Error("Failed to lookup user", zap.String("owner", owner), zap.Error(err))
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		log.Error("Failed to set ownership", zap.String("path", path), zap.Error(err))
		return err
	}
	log.Info("Ownership set", zap.String("path", path), zap.String("owner", owner))
	return nil
}

// WriteOwnedFile writes data to a file and sets ownership to the given user.
func WriteOwnedFile(path string, data []byte, perm os.FileMode, owner string) error {
	log := zap.L().Named("system-filesystem")
	if err := os.WriteFile(path, data, perm); err != nil {
		log.Error("Failed to write file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("write %s: %w", path, err)
	}
	return EnsureOwnership(path, owner)
}

// Rm deletes a file or directory with structured logging.
func Rm(ctx context.Context, path, label string) error {
	traceID := logger.TraceIDFromContext(ctx)
	log := zap.L().With(zap.String("traceID", traceID))

	abs, _ := filepath.Abs(path)
	info, err := os.Stat(abs)

	if os.IsNotExist(err) {
		log.Warn("Path not found", zap.String("label", label), zap.String("path", abs))
		return nil
	}
	if err != nil {
		FailIfPermissionDenied("access "+label, path, err)
		log.Error("Error accessing path", zap.String("label", label), zap.String("path", path), zap.Error(err))
		return err
	}

	var removeErr error
	if info.IsDir() {
		log.Info("Removing directory", zap.String("label", label), zap.String("path", path))
		removeErr = os.RemoveAll(path)
	} else {
		log.Info("Removing file", zap.String("label", label), zap.String("path", path))
		removeErr = os.Remove(path)
	}

	if removeErr != nil {
		FailIfPermissionDenied("remove "+label, path, removeErr)
		log.Error("Failed to remove", zap.String("label", label), zap.String("path", path), zap.Error(removeErr))
		return removeErr
	}

	log.Info("✅ Successfully removed", zap.String("label", label), zap.String("path", path))
	return nil
}

// CopyFile copies a file and applies permissions if specified (permOverride = 0 to keep original).
func CopyFile(src, dst string, permOverride os.FileMode) error {
	log := zap.L().Named("system-filesystem")
	log.Info("Starting file copy", zap.String("source", src), zap.String("destination", dst))

	srcInfo, err := os.Stat(src)
	if err != nil {
		log.Error("Failed to stat source file", zap.String("path", src), zap.Error(err))
		return err
	}
	if !srcInfo.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	in, err := os.Open(src)
	if err != nil {
		log.Error("Failed to open source file", zap.String("path", src), zap.Error(err))
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		log.Error("Failed to create destination file", zap.String("path", dst), zap.Error(err))
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		log.Error("Failed to copy data", zap.String("from", src), zap.String("to", dst), zap.Error(err))
		return err
	}

	mode := permOverride
	if mode == 0 {
		mode = srcInfo.Mode()
	}
	if err := os.Chmod(dst, mode); err != nil {
		log.Warn("Failed to set permissions on destination", zap.String("path", dst), zap.Error(err))
		return err
	}

	log.Info("✅ File copy complete", zap.String("src", src), zap.String("dst", dst))
	return nil
}

// CopyDir recursively copies a directory from src to dst.
func CopyDir(src, dst string) error {
	log := zap.L().Named("system-filesystem")
	log.Info("Starting directory copy", zap.String("source", src), zap.String("destination", dst))

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
			if err := CopyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := CopyFile(srcPath, dstPath, 0); err != nil {
				return err
			}
		}
	}
	log.Info("✅ Directory copy complete", zap.String("source", src), zap.String("destination", dst))
	return nil
}

// ChownRecursive changes ownership of a directory and all contents.
func ChownRecursive(path string, uid, gid int) error {
	log := zap.L().Named("system-filesystem")
	log.Info("Starting recursive chown", zap.String("path", path))
	var firstErr error
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			log.Warn("Walk error during chown", zap.String("path", p), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
			return nil
		}
		if err := os.Chown(p, uid, gid); err != nil {
			log.Warn("Failed to chown", zap.String("path", p), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
		}
		return nil
	})
	return firstErr
}
