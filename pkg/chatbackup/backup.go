// pkg/chatbackup/backup.go
// Core backup logic for AI chat archive
//
// Follows Assess → Intervene → Evaluate pattern:
//   ASSESS:     Discover which AI tools have data, resolve paths
//   INTERVENE:  Run restic backup with resolved paths
//   EVALUATE:   Parse results, update status, report
//
// RATIONALE: Go-native restic invocation instead of embedded bash scripts.
// This is testable, type-safe, and observable via structured logging.

package chatbackup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

type opError struct {
	Op  string
	Err error
}

func (e *opError) Error() string {
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *opError) Unwrap() error {
	return e.Err
}

// resticSummary represents the JSON summary message from restic backup --json.
type resticSummary struct {
	MessageType     string  `json:"message_type"`
	SnapshotID      string  `json:"snapshot_id"`
	FilesNew        int     `json:"files_new"`
	FilesChanged    int     `json:"files_changed"`
	FilesUnmodified int     `json:"files_unmodified"`
	DataAdded       int64   `json:"data_added"`
	TotalDuration   float64 `json:"total_duration"`
}

// RunBackup executes a single backup run.
// It discovers AI tool data, runs restic backup, and returns the result.
//
// ASSESS: Resolve paths, check which tools have data
// INTERVENE: Run restic backup
// EVALUATE: Parse output, update status file
func RunBackup(rc *eos_io.RuntimeContext, config BackupConfig) (*BackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Resolve home directory
	homeDir := config.HomeDir
	if homeDir == "" {
		var err error
		homeDir, err = resolveHomeDir(config.User)
		if err != nil {
			return nil, &opError{
				Op:  "resolve home directory",
				Err: fmt.Errorf("user %q: %w", config.User, err),
			}
		}
	}
	config.HomeDir = homeDir

	logger.Info("Starting chat archive backup",
		zap.String("user", config.User),
		zap.String("home_dir", homeDir),
		zap.Bool("dry_run", config.DryRun),
		zap.Strings("extra_scan_dirs", config.ExtraScanDirs))

	// ASSESS: Resolve restic paths
	repoPath := filepath.Join(homeDir, ResticRepoSubdir)
	passwordFile := filepath.Join(homeDir, ResticPasswordSubdir)
	statusFile := filepath.Join(homeDir, ResticStatusSubdir)
	lockFile := filepath.Join(homeDir, ResticLockSubdir)

	// ASSESS: Discover which AI tools have data
	registry := DefaultToolRegistry()
	paths, toolsFound, skipped := discoverPaths(logger, registry, homeDir)

	// ASSESS: Discover project-level context files in ExtraScanDirs
	projectPaths := discoverProjectContext(logger, config.ExtraScanDirs)
	paths = append(paths, projectPaths...)

	if len(paths) == 0 {
		logger.Info("No AI tool data found to back up")
		return &BackupResult{
			PathsSkipped: skipped,
		}, nil
	}

	logger.Info("Discovered backup paths",
		zap.Int("path_count", len(paths)),
		zap.Strings("tools_found", toolsFound),
		zap.Int("skipped_count", len(skipped)))

	// DRY RUN: Report what would be backed up
	if config.DryRun {
		logger.Info("DRY RUN: Would back up the following paths")
		for _, p := range paths {
			logger.Info("  Would include", zap.String("path", p))
		}
		return &BackupResult{
			PathsBackedUp: paths,
			PathsSkipped:  skipped,
			ToolsFound:    toolsFound,
		}, nil
	}

	// ASSESS: Check restic is available
	if _, err := exec.LookPath("restic"); err != nil {
		updateStatus(logger, statusFile, nil, toolsFound)
		return nil, &opError{
			Op:  "check restic installation",
			Err: fmt.Errorf("restic not found: install with 'sudo apt install restic'"),
		}
	}

	// ASSESS: Check repository is initialized
	if err := checkRepoInitialized(rc.Ctx, repoPath, passwordFile); err != nil {
		updateStatus(logger, statusFile, nil, toolsFound)
		return nil, &opError{
			Op: "check repository initialization",
			Err: fmt.Errorf("restic repository not initialized at %s: %w\n"+
				"Run 'eos backup chats --setup' to initialize", repoPath, err),
		}
	}

	lockHandle, err := acquireBackupLock(lockFile)
	if err != nil {
		updateStatus(logger, statusFile, nil, toolsFound)
		return nil, &opError{Op: "acquire backup lock", Err: err}
	}
	defer releaseBackupLock(lockHandle)

	// INTERVENE: Run restic backup
	result, err := runResticBackup(rc.Ctx, logger, repoPath, passwordFile, paths)
	if err != nil {
		// Update status with failure
		updateStatus(logger, statusFile, nil, toolsFound)
		return nil, fmt.Errorf("restic backup failed: %w", err)
	}

	result.PathsBackedUp = paths
	result.PathsSkipped = skipped
	result.ToolsFound = toolsFound

	// EVALUATE: Update status file
	updateStatus(logger, statusFile, result, toolsFound)

	logger.Info("Chat archive backup completed",
		zap.String("snapshot_id", result.SnapshotID),
		zap.Int("files_new", result.FilesNew),
		zap.Int("files_changed", result.FilesChanged),
		zap.Int64("bytes_added", result.BytesAdded),
		zap.String("duration", result.TotalDuration))

	return result, nil
}

// discoverPaths resolves the tool registry into actual filesystem paths.
// Returns: (existingPaths, toolsFound, skippedPaths)
func discoverPaths(logger otelzap.LoggerWithCtx, registry []ToolSource, homeDir string) ([]string, []string, []string) {
	var paths []string
	var toolsFound []string
	var skipped []string
	seen := make(map[string]bool)

	for _, tool := range registry {
		toolHasData := false
		for _, sp := range tool.Paths {
			discovered, pathSkipped := discoverSourcePath(logger, homeDir, sp)
			if pathSkipped {
				skipped = append(skipped, expandHome(sp.Path, homeDir))
			}
			for _, p := range discovered {
				if !seen[p] {
					paths = append(paths, p)
					seen[p] = true
					toolHasData = true
				}
			}
		}

		if toolHasData {
			toolsFound = append(toolsFound, tool.Name)
			logger.Debug("Found data for tool",
				zap.String("tool", tool.Name))
		}
	}

	sort.Strings(paths)
	sort.Strings(toolsFound)
	sort.Strings(skipped)

	return paths, toolsFound, skipped
}

// discoverProjectContext scans ExtraScanDirs for project-level AI context files.
// Searches up to 4 levels deep for CLAUDE.md, AGENTS.md, .claude/ directories etc.
func discoverProjectContext(logger otelzap.LoggerWithCtx, scanDirs []string) []string {
	var paths []string
	seen := make(map[string]bool)
	patterns := ProjectContextPatterns()

	for _, scanDir := range scanDirs {
		if _, err := os.Stat(scanDir); err != nil {
			logger.Debug("Scan directory not found",
				zap.String("dir", scanDir))
			continue
		}

		// Walk up to 4 levels deep looking for project context files
		err := filepath.WalkDir(scanDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // Skip errors, continue walking
			}

			// Limit depth to 4 levels from scanDir
			rel, _ := filepath.Rel(scanDir, path)
			depth := strings.Count(rel, string(filepath.Separator))
			if depth > 4 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip hidden directories except .claude
			if d.IsDir() && strings.HasPrefix(d.Name(), ".") && d.Name() != ".claude" {
				return filepath.SkipDir
			}

			// Skip common non-project directories
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "vendor", "__pycache__", ".git", "venv", ".venv":
					return filepath.SkipDir
				}
			}

			// Check if this matches any project context pattern
			for _, pattern := range patterns {
				if d.Name() == pattern {
					if !seen[path] {
						paths = append(paths, path)
						seen[path] = true
						logger.Debug("Found project context file",
							zap.String("path", path))
					}
					break
				}
			}

			return nil
		})
		if err != nil {
			logger.Debug("Error walking scan directory",
				zap.String("dir", scanDir),
				zap.Error(err))
		}
	}

	return paths
}

// runResticBackup executes the restic backup command.
func runResticBackup(ctx context.Context, logger otelzap.LoggerWithCtx, repoPath, passwordFile string, paths []string) (*BackupResult, error) {
	args := []string{
		"-r", repoPath,
		"--password-file", passwordFile,
		"backup",
		"--tag", BackupTag,
		"--tag", AutoTag,
		"--json",
	}

	// Add excludes
	for _, exclude := range DefaultExcludes() {
		args = append(args, "--exclude", exclude)
	}

	// Add paths
	args = append(args, paths...)

	logger.Debug("Running restic backup",
		zap.Strings("paths", paths),
		zap.Int("exclude_count", len(DefaultExcludes())))

	backupCtx, cancel := context.WithTimeout(ctx, BackupTimeout)
	defer cancel()

	cmd := exec.CommandContext(backupCtx, "restic", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if backupCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("backup timed out after %s", BackupTimeout)
		}
		return nil, fmt.Errorf("restic backup failed: %w; stderr: %s", err, strings.TrimSpace(stderr.String()))
	}

	// Parse JSON output - restic outputs one JSON object per line
	result := &BackupResult{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var summary resticSummary
		if err := json.Unmarshal([]byte(line), &summary); err != nil {
			continue // Skip non-JSON lines
		}

		if summary.MessageType == "summary" {
			result.SnapshotID = summary.SnapshotID
			result.FilesNew = summary.FilesNew
			result.FilesChanged = summary.FilesChanged
			result.FilesUnmodified = summary.FilesUnmodified
			result.BytesAdded = summary.DataAdded
			result.TotalDuration = fmt.Sprintf("%.1fs", summary.TotalDuration)
		}
	}

	if result.SnapshotID == "" {
		logger.Debug("restic backup output", zap.String("stdout", stdout.String()), zap.String("stderr", stderr.String()))
		return nil, fmt.Errorf("restic returned no summary snapshot")
	}

	return result, nil
}

// checkRepoInitialized verifies the restic repository exists and is accessible.
func checkRepoInitialized(ctx context.Context, repoPath, passwordFile string) error {
	checkCtx, cancel := context.WithTimeout(ctx, ResticCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, "restic",
		"-r", repoPath,
		"--password-file", passwordFile,
		"cat", "config")
	cmd.Stdout = nil
	cmd.Stderr = nil

	return cmd.Run()
}

// updateStatus writes the backup status file for monitoring.
func updateStatus(logger otelzap.LoggerWithCtx, statusFile string, result *BackupResult, toolsFound []string) {
	if err := os.MkdirAll(filepath.Dir(statusFile), ResticDirPerm); err != nil {
		logger.Warn("Failed to create status directory",
			zap.String("path", filepath.Dir(statusFile)),
			zap.Error(err))
		return
	}

	// Read existing status
	status := &BackupStatus{}
	if data, err := os.ReadFile(statusFile); err == nil {
		_ = json.Unmarshal(data, status)
	}

	now := time.Now().Format(time.RFC3339)
	status.ToolsFound = toolsFound

	if result != nil {
		// Success
		status.LastSuccess = now
		status.LastSnapshotID = result.SnapshotID
		status.BytesAdded = result.BytesAdded
		status.SuccessCount++
		if status.FirstBackup == "" {
			status.FirstBackup = now
		}
	} else {
		// Failure
		status.LastFailure = now
		status.FailureCount++
	}

	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		logger.Warn("Failed to marshal status", zap.Error(err))
		return
	}

	tmp := statusFile + ".tmp"
	if err := os.WriteFile(tmp, data, StatusFilePerm); err != nil {
		logger.Warn("Failed to write status file",
			zap.String("path", statusFile),
			zap.Error(err))
		return
	}

	if err := os.Rename(tmp, statusFile); err != nil {
		_ = os.Remove(tmp)
		logger.Warn("Failed to atomically replace status file",
			zap.String("path", statusFile),
			zap.Error(err))
	}
}

// expandHome replaces ~ with the home directory.
func expandHome(path, homeDir string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(homeDir, path[2:])
	}
	if path == "~" {
		return homeDir
	}
	return path
}

// resolveHomeDir returns the home directory for a user.
func resolveHomeDir(username string) (string, error) {
	if username == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not determine home directory: %w", err)
		}
		return home, nil
	}

	if username == "root" {
		return "/root", nil
	}

	if u, err := user.Lookup(username); err == nil && u.HomeDir != "" {
		return u.HomeDir, nil
	}

	homeDir := filepath.Join("/home", username)
	if _, err := os.Stat(homeDir); err != nil {
		return "", fmt.Errorf("home directory not found for user %s at %s: %w", username, homeDir, err)
	}

	return homeDir, nil
}

func discoverSourcePath(logger otelzap.LoggerWithCtx, homeDir string, sp SourcePath) ([]string, bool) {
	resolved := expandHome(sp.Path, homeDir)
	info, err := os.Stat(resolved)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Debug("Error checking path", zap.String("path", resolved), zap.Error(err))
		}
		return nil, true
	}

	if !info.IsDir() {
		if shouldIncludeFile(resolved, sp.Includes, sp.Excludes) {
			return []string{resolved}, false
		}
		return nil, true
	}

	if len(sp.Includes) == 0 {
		entries, err := os.ReadDir(resolved)
		if err != nil || len(entries) == 0 {
			return nil, true
		}
		return []string{resolved}, false
	}

	matches := collectMatchingFiles(resolved, sp.Includes, sp.Excludes)
	return matches, len(matches) == 0
}

func collectMatchingFiles(root string, includes, excludes []string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if path != root && pathMatchAny(d.Name(), excludes) {
				return filepath.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}

		if !shouldIncludeFile(rel, includes, excludes) {
			return nil
		}

		out = append(out, path)
		return nil
	})

	sort.Strings(out)
	return out
}

func shouldIncludeFile(path string, includes, excludes []string) bool {
	if pathMatchAny(path, excludes) {
		return false
	}

	if len(includes) == 0 {
		return true
	}

	return pathMatchAny(path, includes)
}

func pathMatchAny(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, pattern := range patterns {
		if pattern == path || pattern == base {
			return true
		}

		if ok, err := filepath.Match(pattern, base); err == nil && ok {
			return true
		}
		if ok, err := filepath.Match(pattern, path); err == nil && ok {
			return true
		}
	}
	return false
}

func acquireBackupLock(lockFile string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(lockFile), ResticDirPerm); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}

	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another backup is already running")
	}

	return f, nil
}

func releaseBackupLock(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}
