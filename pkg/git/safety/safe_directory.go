package safety

import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
    "github.com/uptrace/opentelemetry-go-extra/otelzap"
    "go.uber.org/zap"
)

// EnsureSafeDirectory registers the repository path in git's global safe.directory.
//
// This prevents "detected dubious ownership" errors when the repository lives
// in a system-owned directory (e.g., /opt) or when the current user differs
// from the repository owner. The entry is added for the current user and, when
// running via sudo, also for the original user if detectable.
//
// Best-effort: failures are returned to the caller to log as warnings; they
// should not abort repository creation.
func EnsureSafeDirectory(rc *eos_io.RuntimeContext, repoPath string) error {
    logger := otelzap.Ctx(rc.Ctx)

    absPath, err := filepath.Abs(repoPath)
    if err != nil {
        return fmt.Errorf("resolve absolute path: %w", err)
    }

    // If already configured, nothing to do
    configured, err := isPathInSafeDirectory(rc.Ctx, absPath)
    if err != nil {
        // Non-fatal; continue and try to add
        logger.Debug("Could not check git safe.directory entries", zap.Error(err))
    } else if configured {
        logger.Debug("git safe.directory already includes path", zap.String("path", absPath))
        return nil
    }

    // Add for current user
    if err := addSafeDirectory(rc.Ctx, absPath); err != nil {
        return err
    }
    logger.Info("Registered repository as safe for git", zap.String("path", absPath))

    // If running via sudo, also add for the original user so future non-root
    // git operations don't fail with dubious ownership.
    if os.Geteuid() == 0 {
        if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" {
            // Only attempt if sudo is available; if it fails, log and continue
            cmd := exec.CommandContext(rc.Ctx, "sudo", "-u", sudoUser, "git", "config", "--global", "--add", "safe.directory", absPath)
            if out, err := cmd.CombinedOutput(); err != nil {
                logger.Warn("Failed to add safe.directory for original sudo user",
                    zap.String("user", sudoUser),
                    zap.String("output", strings.TrimSpace(string(out))),
                    zap.Error(err))
            } else {
                logger.Info("Registered repository as safe for original sudo user",
                    zap.String("user", sudoUser),
                    zap.String("path", absPath))
            }
        }
    }

    return nil
}

func isPathInSafeDirectory(ctx context.Context, path string) (bool, error) {
    cmd := exec.CommandContext(ctx, "git", "config", "--global", "--get-all", "safe.directory")
    out, err := cmd.CombinedOutput()
    if err != nil {
        // git returns exit code 1 if key is missing; treat as not configured
        if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
            return false, nil
        }
        return false, fmt.Errorf("git config query failed: %w (%s)", err, strings.TrimSpace(string(out)))
    }

    entries := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
    for _, e := range entries {
        e = strings.TrimSpace(e)
        if e == "" {
            continue
        }
        if e == "*" {
            // Global trust; path is implicitly covered
            return true, nil
        }
        if samePath(e, path) {
            return true, nil
        }
    }
    return false, nil
}

func addSafeDirectory(ctx context.Context, path string) error {
    cmd := exec.CommandContext(ctx, "git", "config", "--global", "--add", "safe.directory", path)
    if out, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("git config --add safe.directory failed: %w (%s)", err, strings.TrimSpace(string(out)))
    }
    return nil
}

func samePath(a, b string) bool {
    // Compare with simple normalization; filepath.Abs already applied to b
    // Keep comparison case-sensitive (Linux) and lenient for trailing slashes
    cleanA := strings.TrimRight(filepath.Clean(a), string(os.PathSeparator))
    cleanB := strings.TrimRight(filepath.Clean(b), string(os.PathSeparator))
    return cleanA == cleanB
}

