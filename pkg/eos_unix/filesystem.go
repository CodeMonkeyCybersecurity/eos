// pkg/unix/filesystem.go

package eos_unix

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// MkdirP ensures path exists with perm bits.
func MkdirP(ctx context.Context, path string, perm os.FileMode) error {
	_, span := telemetry.Start(ctx, "filesystem.MkdirP",
		attribute.String("path", path),
	)
	defer span.End()

	abs, err := filepath.Abs(path)
	if err != nil {
		otelzap.Ctx(ctx).Error("abs failed", zap.Error(err), zap.String("path", path))
		return cerr.Wrapf(err, "abs %q", path)
	}

	info, err := os.Stat(abs)
	if os.IsNotExist(err) {
		otelzap.Ctx(ctx).Info("creating directory", zap.String("path", abs))
		if err := os.MkdirAll(abs, perm); err != nil {
			if os.IsPermission(err) {
				return cerr.Newf("permission denied creating %s", abs)
			}
			return cerr.Wrapf(err, "mkdir %s", abs)
		}
	} else if err != nil {
		otelzap.Ctx(ctx).Error("stat failed", zap.Error(err), zap.String("path", abs))
		return cerr.Wrapf(err, "stat %s", abs)
	} else if !info.IsDir() {
		return cerr.Newf("%s exists but is not a directory", abs)
	}

	return nil
}

// EnsureOwnership sets the owner of `path`. On Unix, it calls os.Chown;
// on Windows this could be replaced with ACL calls under a build tag.
// If owner is empty string, ownership is not changed (file keeps current owner).
func EnsureOwnership(ctx context.Context, path, owner string) error {
	log := otelzap.Ctx(ctx)

	// Skip ownership change if no owner specified
	if owner == "" {
		log.Debug("Skipping ownership change (no owner specified)", zap.String("path", path))
		return nil
	}

	// Lookup target user/group
	uid, gid, err := LookupUser(ctx, owner)
	if err != nil {
		log.Error("user lookup failed",
			zap.String("owner", owner),
			zap.Error(err))
		return cerr.Wrapf(err, "lookup user %q", owner)
	}

	log.Debug("Setting file ownership",
		zap.String("path", path),
		zap.String("owner", owner),
		zap.Int("uid", uid),
		zap.Int("gid", gid))

	// Perform chown
	if err := os.Chown(path, uid, gid); err != nil {
		log.Error("chown failed",
			zap.String("path", path),
			zap.String("intended_owner", owner),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Error(err))
		return cerr.Wrapf(err, "chown %s to %s", path, owner)
	}

	// Verify ownership was set correctly
	stat, err := os.Stat(path)
	if err != nil {
		log.Warn("chown succeeded but verification stat failed",
			zap.String("path", path),
			zap.Error(err))
	} else {
		sys := stat.Sys()
		log.Debug("Ownership set successfully",
			zap.String("path", path),
			zap.String("owner", owner),
			zap.Int("uid", uid),
			zap.Int("gid", gid),
			zap.Any("stat_sys", sys))
	}

	return nil
}

// MultiMkdirP batches MkdirP over many paths.
func MultiMkdirP(ctx context.Context, paths []string, perm os.FileMode) error {
	for _, p := range paths {
		if err := MkdirP(ctx, p, perm); err != nil {
			return cerr.Wrapf(err, "ensure %s", p)
		}
	}
	return nil
}

// WriteFile writes data to a file and sets ownership to the given user.
func WriteFile(ctx context.Context, path string, data []byte, perm os.FileMode, owner string) error {
	log := otelzap.Ctx(ctx)

	// Pre-operation logging
	log.Debug("Writing file with ownership",
		zap.String("path", path),
		zap.String("owner", owner),
		zap.String("permissions", perm.String()),
		zap.Int("size_bytes", len(data)))

	// Write file
	if err := os.WriteFile(path, data, perm); err != nil {
		log.Error("Failed to write file",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("write %s: %w", path, err)
	}

	// Set ownership
	if err := EnsureOwnership(ctx, path, owner); err != nil {
		log.Error("Failed to set ownership after writing file",
			zap.String("path", path),
			zap.String("intended_owner", owner),
			zap.Error(err))
		return err
	}

	// Post-operation verification logging
	stat, err := os.Stat(path)
	if err != nil {
		log.Warn("File written but stat failed",
			zap.String("path", path),
			zap.Error(err))
	} else {
		log.Info("File written successfully with ownership",
			zap.String("path", path),
			zap.String("owner", owner),
			zap.String("permissions", stat.Mode().String()),
			zap.Int64("size", stat.Size()))
	}

	return nil
}

// RmRF removes file or dir, with tracing, policy, validation.
func RmRF(ctx context.Context, path, label string) error {

	abs, err := filepath.Abs(path)
	if err != nil {
		otelzap.Ctx(ctx).Error("abs failed", zap.Error(err))
		return cerr.Wrapf(err, "abs %q", path)
	}
	info, err := os.Stat(abs)
	if os.IsNotExist(err) {
		otelzap.Ctx(ctx).Warn("not found", zap.String("path", abs))
		return nil
	} else if err != nil {
		otelzap.Ctx(ctx).Error("stat failed", zap.Error(err))
		return cerr.Wrapf(err, "stat %s", abs)
	}

	otelzap.Ctx(ctx).Info("removing", zap.String("path", abs))
	var rmErr error
	if info.IsDir() {
		rmErr = os.RemoveAll(abs)
	} else {
		rmErr = os.Remove(abs)
	}
	if rmErr != nil {
		if os.IsPermission(rmErr) {
			return cerr.Newf("permission denied removing %s", abs)
		}
		otelzap.Ctx(ctx).Error("remove failed", zap.Error(rmErr))
		return cerr.Wrapf(rmErr, "remove %s", abs)
	}
	otelzap.Ctx(ctx).Info("removed", zap.String("path", abs))
	return nil
}

// CopyFile copies one file (ensuring target dir).
func CopyFile(ctx context.Context, src, dst string, perm os.FileMode) error {

	info, err := os.Stat(src)
	if err != nil {
		return cerr.Wrapf(err, "stat %s", src)
	}
	if !info.Mode().IsRegular() {
		return cerr.Newf("%s is not a file", src)
	}

	in, err := os.Open(src)
	if err != nil {
		return cerr.Wrapf(err, "open %s", src)
	}
	defer func() {
		if cerr := in.Close(); cerr != nil {
			logger := otelzap.Ctx(ctx)
			logger.Error("failed to close source file", zap.String("file", src), zap.Error(cerr))
		}
	}()

	if err := MkdirP(ctx, filepath.Dir(dst), 0o755); err != nil {
		return cerr.Wrapf(err, "ensure dir for %s", dst)
	}

	out, err := os.Create(dst)
	if err != nil {
		return cerr.Wrapf(err, "create %s", dst)
	}
	defer func() {
		if cerr := out.Close(); cerr != nil {
			logger := otelzap.Ctx(ctx)
			logger.Error("failed to close destination file", zap.String("file", dst), zap.Error(cerr))
		}
	}()

	if _, err := io.Copy(out, in); err != nil {
		return cerr.Wrapf(err, "copy %s→%s", src, dst)
	}
	if err := out.Chmod(perm); err != nil {
		return cerr.Wrapf(err, "chmod %s", dst)
	}

	otelzap.Ctx(ctx).Info("copied file", zap.String("src", src), zap.String("dst", dst))
	return nil
}

// CopyR recursively copies a directory tree.
func CopyR(ctx context.Context, src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return cerr.Wrapf(err, "stat %s", src)
	}
	if !info.IsDir() {
		return cerr.Newf("source %s is not a directory", src)
	}

	if err := MkdirP(ctx, dst, info.Mode()); err != nil {
		return cerr.Wrapf(err, "ensure dir %s", dst)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return cerr.Wrapf(err, "read dir %s", src)
	}
	for _, e := range entries {
		s, d := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := CopyR(ctx, s, d); err != nil {
				return err
			}
		} else {
			if err := CopyFile(ctx, s, d, info.Mode()); err != nil {
				return err
			}
		}
	}

	otelzap.Ctx(ctx).Info("directory copied", zap.String("src", src), zap.String("dst", dst))
	return nil
}

// ChownR recursively chowns a directory tree.
func ChownR(ctx context.Context, root string, uid, gid int) error {
	_, span := telemetry.Start(ctx, "filesystem.ChownR",
		attribute.String("root", root),
		attribute.Int("uid", uid),
		attribute.Int("gid", gid),
	)
	defer span.End()

	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			otelzap.Ctx(ctx).Warn("walk failed", zap.String("path", p), zap.Error(err))
			return nil // continue
		}
		if err := os.Chown(p, uid, gid); err != nil {
			otelzap.Ctx(ctx).Warn("chown failed", zap.String("path", p), zap.Error(err))
		}
		return nil
	})
}

// in eos_unix:
func ChmodR(ctx context.Context, path string, perm os.FileMode) error {
	return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chmod(p, perm)
	})
}
