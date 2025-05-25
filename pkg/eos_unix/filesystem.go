// pkg/unix/filesystem.go

package eos_unix

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

var (
	log = zap.L().Named("filesystem")
)

// MkdirP ensures path exists with perm bits.
func MkdirP(ctx context.Context, path string, perm os.FileMode) error {
	_, span := telemetry.Start(ctx, "filesystem.MkdirP",
		attribute.String("path", path),
	)
	defer span.End()

	abs, err := filepath.Abs(path)
	if err != nil {
		zap.L().Error("abs failed", zap.Error(err), zap.String("path", path))
		return cerr.Wrapf(err, "abs %q", path)
	}

	info, err := os.Stat(abs)
	if os.IsNotExist(err) {
		zap.L().Info("creating directory", zap.String("path", abs))
		if err := os.MkdirAll(abs, perm); err != nil {
			if os.IsPermission(err) {
				return cerr.Newf("permission denied creating %s", abs)
			}
			return cerr.Wrapf(err, "mkdir %s", abs)
		}
	} else if err != nil {
		zap.L().Error("stat failed", zap.Error(err), zap.String("path", abs))
		return cerr.Wrapf(err, "stat %s", abs)
	} else if !info.IsDir() {
		return cerr.Newf("%s exists but is not a directory", abs)
	}

	return nil
}

// EnsureOwnership sets the owner of `path`. On Unix, it calls os.Chown;
// on Windows this could be replaced with ACL calls under a build tag.
func EnsureOwnership(path, owner string) error {
	uid, gid, err := LookupUser(owner) // assume elsewhere in eos_unix
	if err != nil {
		log.Error("user lookup failed", zap.String("owner", owner), zap.Error(err))
		return cerr.Wrapf(err, "lookup user %q", owner)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		log.Error("chown failed", zap.String("path", path), zap.Error(err))
		return cerr.Wrapf(err, "chown %s to %s", path, owner)
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
func WriteFile(path string, data []byte, perm os.FileMode, owner string) error {
	log := zap.L().Named("system-filesystem")
	if err := os.WriteFile(path, data, perm); err != nil {
		log.Error("Failed to write file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("write %s: %w", path, err)
	}
	return EnsureOwnership(path, owner)
}

// RmRF removes file or dir, with tracing, policy, validation.
func RmRF(ctx context.Context, path, label string) error {
	ctx, span := telemetry.Start(ctx, "filesystem.RmRF",
		attribute.String("path", path),
		attribute.String("label", label),
	)
	defer span.End()

	traceID := logger.TraceIDFromContext(ctx)
	lg := log.With(zap.String("traceID", traceID), zap.String("label", label))

	abs, err := filepath.Abs(path)
	if err != nil {
		lg.Error("abs failed", zap.Error(err))
		return cerr.Wrapf(err, "abs %q", path)
	}
	info, err := os.Stat(abs)
	if os.IsNotExist(err) {
		lg.Warn("not found", zap.String("path", abs))
		return nil
	} else if err != nil {
		lg.Error("stat failed", zap.Error(err))
		return cerr.Wrapf(err, "stat %s", abs)
	}

	lg.Info("removing", zap.String("path", abs))
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
		lg.Error("remove failed", zap.Error(rmErr))
		return cerr.Wrapf(rmErr, "remove %s", abs)
	}
	lg.Info("removed", zap.String("path", abs))
	return nil
}

// CopyFile copies one file (ensuring target dir).
func CopyFile(ctx context.Context, src, dst string, perm os.FileMode) error {
	ctx, span := telemetry.Start(ctx, "filesystem.CopyFile",
		attribute.String("src", src),
		attribute.String("dst", dst),
	)
	defer span.End()

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
	defer in.Close()

	if err := MkdirP(ctx, filepath.Dir(dst), 0o755); err != nil {
		return cerr.Wrapf(err, "ensure dir for %s", dst)
	}

	out, err := os.Create(dst)
	if err != nil {
		return cerr.Wrapf(err, "create %s", dst)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return cerr.Wrapf(err, "copy %s→%s", src, dst)
	}
	if err := out.Chmod(perm); err != nil {
		return cerr.Wrapf(err, "chmod %s", dst)
	}

	zap.L().Info("copied file", zap.String("src", src), zap.String("dst", dst))
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

	zap.L().Info("directory copied", zap.String("src", src), zap.String("dst", dst))
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
			zap.L().Warn("walk failed", zap.String("path", p), zap.Error(err))
			return nil // continue
		}
		if err := os.Chown(p, uid, gid); err != nil {
			zap.L().Warn("chown failed", zap.String("path", p), zap.Error(err))
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
