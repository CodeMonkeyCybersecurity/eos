/* pkg/system/lifecycle.go */

package system

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

/**/
// should probs move these into system.EnsureOwnedDir
// --- helper: ensure a dir exists with the right owner & perms ---
func EnsureOwnedDir(path string, perm os.FileMode, owner string) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	uid, gid, err := LookupUser(owner)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", owner, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

/**/

/**/
// should probs move these into system.WriteOwnedFile
// --- helper: write a file and chown to owner ---
func WriteOwnedFile(path string, data []byte, perm os.FileMode, owner string) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	uid, gid, err := LookupUser(owner)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", owner, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

/**/

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
		FailIfPermissionDenied(log, "access "+label, path, err)
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
		FailIfPermissionDenied(log, "remove "+label, path, err)
		log.Error("Failed to remove", zap.String("label", label), zap.String("path", path), zap.Error(err))
		fmt.Printf("❌ Failed to remove %s (%s): %v\n", label, path, err)
		return err
	}

	log.Info("Successfully removed", zap.String("label", label), zap.String("path", path))
	fmt.Printf("✅ %s removed: %s\n", label, path)
	return nil
}

// CopyFile copies a file from src to dst and optionally overrides permissions.
// Pass permOverride = 0 to preserve the original file's permissions.
func CopyFile(src, dst string, permOverride os.FileMode, log *zap.Logger) error {
	log.Info("📂 Starting file copy",
		zap.String("source", src),
		zap.String("destination", dst),
		zap.String("perm_override", fmt.Sprintf("%#o", permOverride)),
	)

	// Step 1: Stat the source
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		log.Error("❌ Failed to stat source file", zap.String("path", src), zap.Error(err))
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		log.Error("❌ Source is not a regular file", zap.String("path", src), zap.String("mode", sourceFileStat.Mode().String()))
		return fmt.Errorf("%s is not a regular file", src)
	}

	log.Info("📄 Source file is valid",
		zap.String("path", src),
		zap.String("size", fmt.Sprintf("%d bytes", sourceFileStat.Size())),
		zap.String("mode", sourceFileStat.Mode().String()),
	)

	// Step 2: Open the source
	source, err := os.Open(src)
	if err != nil {
		log.Error("❌ Failed to open source file", zap.String("path", src), zap.Error(err))
		return err
	}
	defer func() {
		if cerr := source.Close(); cerr != nil {
			log.Warn("⚠️ Failed to close source file", zap.String("path", src), zap.Error(cerr))
		}
	}()

	// Step 3: Create the destination
	destination, err := os.Create(dst)
	if err != nil {
		log.Error("❌ Failed to create destination file", zap.String("path", dst), zap.Error(err))
		return err
	}
	defer func() {
		if cerr := destination.Close(); cerr != nil {
			log.Warn("⚠️ Failed to close destination file", zap.String("path", dst), zap.Error(cerr))
		}
	}()

	log.Info("✍️ Writing file contents", zap.String("from", src), zap.String("to", dst))
	if _, err := io.Copy(destination, source); err != nil {
		log.Error("❌ Failed to copy data", zap.String("from", src), zap.String("to", dst), zap.Error(err))
		return err
	}

	// Step 4: Apply final permissions
	finalMode := permOverride
	if permOverride == 0 {
		finalMode = sourceFileStat.Mode()
		log.Info("🔐 Preserving source permissions", zap.String("mode", fmt.Sprintf("%#o", finalMode)))
	} else {
		log.Info("🔐 Overriding permissions", zap.String("new_mode", fmt.Sprintf("%#o", finalMode)))
	}

	if err := os.Chmod(dst, finalMode); err != nil {
		log.Warn("❌ Failed to set permissions on destination", zap.String("path", dst), zap.Error(err))
		return err
	}

	log.Info("✅ File copy complete",
		zap.String("src", src),
		zap.String("dst", dst),
		zap.String("mode_applied", fmt.Sprintf("%#o", finalMode)),
	)

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
			if err := CopyFile(srcPath, dstPath, 0, zap.L()); err != nil {
				return err
			}
		}
	}

	return nil
}

// ChownRecursive changes ownership of a directory and all files within to uid:gid.
func ChownRecursive(path string, uid, gid int, log *zap.Logger) error {
	var firstErr error
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			log.Warn("⚠️ Walk error during chown", zap.String("path", p), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
			return nil // Keep walking
		}
		if err := os.Chown(p, uid, gid); err != nil {
			log.Warn("⚠️ Failed to chown", zap.String("path", p), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
		}
		return nil // Keep walking
	})
	if err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
