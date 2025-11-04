// pkg/git/preflight_comprehensive.go
//
// Comprehensive git environment validation with edge case handling
// Extends preflight.go with advanced checks for production robustness

package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GitVersion represents a parsed git version
type GitVersion struct {
	Major int
	Minor int
	Patch int
	Full  string
}

func (v GitVersion) String() string {
	return v.Full
}

// IsAtLeast checks if version is at least the specified version
func (v GitVersion) IsAtLeast(major, minor int) bool {
	if v.Major > major {
		return true
	}
	if v.Major == major && v.Minor >= minor {
		return true
	}
	return false
}

// RepoState represents the current state of a git repository
type RepoState struct {
	Exists             bool
	Valid              bool
	Clean              bool
	DetachedHead       bool
	CurrentBranch      string
	UncommittedChanges string
	UntrackedFiles     []string
}

// CheckGitVersionComprehensive checks git version and warns about old versions
func CheckGitVersionComprehensive(ctx context.Context) (*GitVersion, error) {
	logger := otelzap.Ctx(ctx)

	cmd := exec.CommandContext(ctx, "git", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, eos_err.NewDependencyError(
			"git",
			"repository operations",
			"Install git: sudo apt-get install git",
			"Or download from: https://git-scm.com/downloads",
		)
	}

	// Parse version string: "git version 2.34.1"
	versionStr := strings.TrimSpace(string(output))
	version := parseGitVersion(versionStr)

	logger.Debug("Git version detected",
		zap.String("version", version.String()),
		zap.Int("major", version.Major),
		zap.Int("minor", version.Minor))

	// Warn about old versions
	if !version.IsAtLeast(2, 0) {
		logger.Warn("Git version is very old",
			zap.String("current", version.String()),
			zap.String("recommended", "2.0+"),
			zap.String("note", "Some features may not work correctly"))
	}

	return version, nil
}

// parseGitVersion extracts version numbers from git --version output
func parseGitVersion(versionStr string) *GitVersion {
	// Match pattern: git version X.Y.Z
	re := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(versionStr)

	if len(matches) < 4 {
		// Fallback to assuming modern version if we can't parse
		return &GitVersion{Major: 2, Minor: 0, Patch: 0, Full: versionStr}
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])

	return &GitVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
		Full:  versionStr,
	}
}

// CheckRepositoryStateDetailed examines existing repository state in detail
// Returns RepoState and an error only if state is invalid
// Note: Different from operations.go CheckRepositoryState which is simpler
func CheckRepositoryStateDetailed(ctx context.Context, path string) (*RepoState, error) {
	logger := otelzap.Ctx(ctx)

	state := &RepoState{}

	// Check if .git exists
	gitDir := filepath.Join(path, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if os.IsNotExist(err) {
			state.Exists = false
			return state, nil
		}
		return nil, eos_err.NewFilesystemError(
			"Cannot access .git directory",
			err,
			fmt.Sprintf("Check permissions on %s", gitDir),
		)
	}

	state.Exists = true

	// Validate it's a real repository
	cmd := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "--git-dir")
	if err := cmd.Run(); err != nil {
		logger.Error(".git directory exists but repository is corrupted",
			zap.String("path", path),
			zap.Error(err))

		return state, eos_err.NewGitError(
			"Git repository is corrupted",
			err,
			fmt.Sprintf("Backup and remove: mv %s %s.backup", gitDir, gitDir),
			"Then reinitialize the repository",
		)
	}

	state.Valid = true

	// Check for detached HEAD
	cmd = exec.CommandContext(ctx, "git", "-C", path, "symbolic-ref", "-q", "HEAD")
	if err := cmd.Run(); err != nil {
		state.DetachedHead = true
		logger.Warn("Repository is in detached HEAD state",
			zap.String("path", path))
	}

	// Get current branch
	cmd = exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "--abbrev-ref", "HEAD")
	if output, err := cmd.Output(); err == nil {
		state.CurrentBranch = strings.TrimSpace(string(output))
	}

	// Check for uncommitted changes
	cmd = exec.CommandContext(ctx, "git", "-C", path, "status", "--porcelain")
	if output, err := cmd.Output(); err == nil {
		statusOutput := strings.TrimSpace(string(output))
		if statusOutput != "" {
			state.Clean = false
			state.UncommittedChanges = statusOutput

			// Parse untracked files
			lines := strings.Split(statusOutput, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "?? ") {
					state.UntrackedFiles = append(state.UntrackedFiles, strings.TrimPrefix(line, "?? "))
				}
			}
		} else {
			state.Clean = true
		}
	}

	logger.Debug("Repository state checked",
		zap.Bool("exists", state.Exists),
		zap.Bool("valid", state.Valid),
		zap.Bool("clean", state.Clean),
		zap.Bool("detached_head", state.DetachedHead),
		zap.String("branch", state.CurrentBranch))

	return state, nil
}

// CheckDiskSpace verifies sufficient disk space for git operations
func CheckDiskSpace(ctx context.Context, path string, minBytes uint64) error {
	logger := otelzap.Ctx(ctx)

	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return eos_err.NewFilesystemError(
			"Cannot check disk space",
			err,
			fmt.Sprintf("Verify path exists: %s", path),
		)
	}

	availableBytes := stat.Bavail * uint64(stat.Bsize)
	availableGB := availableBytes / (1024 * 1024 * 1024)
	requiredGB := minBytes / (1024 * 1024 * 1024)

	logger.Debug("Disk space checked",
		zap.Uint64("available_gb", availableGB),
		zap.Uint64("required_gb", requiredGB))

	if availableBytes < minBytes {
		return eos_err.NewFilesystemError(
			"Insufficient disk space",
			nil,
			fmt.Sprintf("Required: %dGB, Available: %dGB", requiredGB, availableGB),
			"Free up space with: docker system prune -a",
			"Or: sudo apt clean",
		)
	}

	if availableBytes < minBytes*2 {
		logger.Warn("Low disk space",
			zap.Uint64("available_gb", availableGB),
			zap.String("warning", "Consider freeing up space"))
	}

	return nil
}

// CheckWritePermissions verifies we can write to the directory
func CheckWritePermissions(ctx context.Context, path string) error {
	logger := otelzap.Ctx(ctx)

	// Ensure directory exists
	if err := os.MkdirAll(path, 0755); err != nil {
		return eos_err.NewPermissionError(
			path,
			"create directory",
			fmt.Sprintf("Check parent directory permissions: ls -la %s", filepath.Dir(path)),
			"Fix ownership: sudo chown -R $USER:$USER "+filepath.Dir(path),
		)
	}

	// Try to write a test file
	testFile := filepath.Join(path, ".eos-write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return eos_err.NewPermissionError(
			path,
			"write",
			fmt.Sprintf("Check directory permissions: ls -la %s", path),
			"Fix ownership: sudo chown -R $USER:$USER "+path,
		)
	}

	// Clean up test file
	os.Remove(testFile)

	logger.Debug("Write permissions verified", zap.String("path", path))
	return nil
}

// AcquireRepositoryLock prevents concurrent operations on same repository
// Returns a cleanup function that must be called to release the lock
func AcquireRepositoryLock(ctx context.Context, path string) (func(), error) {
	logger := otelzap.Ctx(ctx)

	lockFile := filepath.Join(path, ".eos.lock")

	// Try to create lock file exclusively
	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			// Lock exists - check if stale
			if isLockStale(lockFile) {
				logger.Warn("Removing stale lock file", zap.String("lockfile", lockFile))
				os.Remove(lockFile)
				// Retry
				return AcquireRepositoryLock(ctx, path)
			}

			return nil, eos_err.NewFilesystemError(
				"Another EOS operation is in progress on this repository",
				nil,
				"Wait for the other operation to complete",
				fmt.Sprintf("Or remove stale lock: rm %s", lockFile),
			)
		}
		return nil, eos_err.NewFilesystemError(
			"Cannot create lock file",
			err,
			fmt.Sprintf("Check permissions on %s", path),
		)
	}

	// Write our PID to lock file
	fmt.Fprintf(f, "%d\n", os.Getpid())
	f.Close()

	logger.Debug("Repository lock acquired", zap.String("lockfile", lockFile))

	// Return cleanup function
	cleanup := func() {
		if err := os.Remove(lockFile); err != nil {
			logger.Warn("Failed to remove lock file",
				zap.String("lockfile", lockFile),
				zap.Error(err))
		} else {
			logger.Debug("Repository lock released", zap.String("lockfile", lockFile))
		}
	}

	return cleanup, nil
}

// isLockStale checks if a lock file represents a dead process
func isLockStale(lockFile string) bool {
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return true // Can't read, consider stale
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return true // Invalid PID, consider stale
	}

	// Check if process exists by sending signal 0
	process, err := os.FindProcess(pid)
	if err != nil {
		return true // Process doesn't exist
	}

	err = process.Signal(syscall.Signal(0))
	return err != nil // If signal fails, process is dead
}

// ValidatePathSafety checks for dangerous path conditions
func ValidatePathSafety(ctx context.Context, path string) error {
	logger := otelzap.Ctx(ctx)

	// Resolve symlinks
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Path doesn't exist yet - that's okay
			realPath = path
		} else {
			return eos_err.NewFilesystemError(
				"Cannot resolve path (broken symlink?)",
				err,
				fmt.Sprintf("Check path: %s", path),
			)
		}
	}

	// Warn if in temporary location
	if strings.HasPrefix(realPath, "/tmp") || strings.HasPrefix(realPath, os.TempDir()) {
		logger.Warn("Repository is in temporary directory",
			zap.String("path", realPath),
			zap.String("warning", "Contents may be deleted on reboot"))
	}

	// Check for path traversal attempts
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return eos_err.NewValidationError(
			"Path traversal detected",
			fmt.Sprintf("Suspicious path: %s", path),
			"Use absolute or simple relative paths only",
		)
	}

	logger.Debug("Path safety validated", zap.String("path", realPath))
	return nil
}

// CheckGitConfigFiles validates git config files aren't corrupted
func CheckGitConfigFiles(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Warn("Cannot determine home directory", zap.Error(err))
		return nil // Not critical
	}

	globalConfig := filepath.Join(homeDir, ".gitconfig")

	// Check if global config exists and is readable
	if _, err := os.Stat(globalConfig); err == nil {
		// Try to read it
		if _, err := os.ReadFile(globalConfig); err != nil {
			return eos_err.NewFilesystemError(
				"Git global config exists but cannot be read",
				err,
				fmt.Sprintf("Check permissions: ls -la %s", globalConfig),
				"Fix permissions: chmod 644 "+globalConfig,
			)
		}

		// Try to parse it (git will validate)
		cmd := exec.CommandContext(ctx, "git", "config", "--global", "--list")
		if err := cmd.Run(); err != nil {
			logger.Warn("Git global config may be corrupted",
				zap.String("config", globalConfig),
				zap.Error(err))
			// Don't fail - just warn
		}
	}

	logger.Debug("Git config files validated")
	return nil
}
