package chats

// backup.go — Incremental chat backup with SHA-256 deduplication.
//
// Follows Assess -> Intervene -> Evaluate pattern:
//
//	ASSESS:     Collect chat files to staging, generate manifest, diff against previous.
//	INTERVENE:  Create tar.gz archive of new/changed files, rotate manifest.
//	EVALUATE:   Log results, return structured BackupResult.

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BackupConfig holds configuration for a chat backup run.
type BackupConfig struct {
	// RepoRoot is the git repository root (backup destination is relative to this).
	RepoRoot string
	// HomeDir is the user's home directory for resolving ~ paths.
	HomeDir string
	// ConfigDir is the platform config directory (XDG_CONFIG_HOME / Library/Application Support).
	ConfigDir string
	// DryRun shows what would be backed up without creating an archive.
	DryRun bool
}

// BackupResult holds the outcome of a backup run.
type BackupResult struct {
	// ArchivePath is the path to the created tar.gz archive (empty if dry-run or no changes).
	ArchivePath string
	// NewFiles is the count of files not present in the previous manifest.
	NewFiles int
	// ChangedFiles is the count of files with different SHA-256 hashes.
	ChangedFiles int
	// UnchangedFiles is the count of files with identical hashes (skipped).
	UnchangedFiles int
	// SourcesFound is the number of AI tools with data on this machine.
	SourcesFound int
	// TotalFiles is the total number of files collected before dedup.
	TotalFiles int
}

// manifestEntry is a filename -> SHA-256 hash mapping.
type manifestEntry struct {
	File string
	Hash string
}

// RunBackup discovers chat sources, deduplicates via SHA-256 manifest, and creates
// an incremental tar.gz archive. Follows Assess -> Intervene -> Evaluate pattern.
func RunBackup(rc *eos_io.RuntimeContext, config BackupConfig) (*BackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ═══════════════════════════════════════════════════════════════════
	// ASSESS: Collect sources and build dedup manifest
	// ═══════════════════════════════════════════════════════════════════

	sources := DefaultSources(config.HomeDir, config.ConfigDir, config.RepoRoot)

	stagingDir, err := os.MkdirTemp("", "eos-chat-backup-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	sourcesFound := 0
	totalCollected := 0
	for _, src := range sources {
		n := collectSource(logger, src, stagingDir)
		if n > 0 {
			logger.Info("Collected files",
				zap.String("tool", src.Name),
				zap.Int("files", n))
			sourcesFound++
			totalCollected += n
		}
	}

	if totalCollected == 0 {
		logger.Info("No chat files found on this machine")
		return &BackupResult{}, nil
	}

	newManifest, err := generateManifest(stagingDir)
	if err != nil {
		return nil, fmt.Errorf("failed to generate manifest: %w", err)
	}

	backupDir := filepath.Join(config.RepoRoot, BackupSubdir)
	prevManifest := loadManifest(filepath.Join(backupDir, ManifestFile))
	newFiles, changedFiles, unchangedFiles, filesToArchive := diffManifests(newManifest, prevManifest)

	result := &BackupResult{
		NewFiles:       newFiles,
		ChangedFiles:   changedFiles,
		UnchangedFiles: unchangedFiles,
		SourcesFound:   sourcesFound,
		TotalFiles:     totalCollected,
	}

	logger.Info("Deduplication complete",
		zap.Int("new", newFiles),
		zap.Int("changed", changedFiles),
		zap.Int("unchanged", unchangedFiles))

	if len(filesToArchive) == 0 {
		logger.Info("No new or changed files since last backup")
		return result, nil
	}

	if config.DryRun {
		logger.Info("DRY RUN: would archive files",
			zap.Int("file_count", len(filesToArchive)))
		return result, nil
	}

	// ═══════════════════════════════════════════════════════════════════
	// INTERVENE: Create archive and update manifest
	// ═══════════════════════════════════════════════════════════════════

	if err := os.MkdirAll(backupDir, BackupDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	if gitErr := ensureGitignore(config.RepoRoot); gitErr != nil {
		logger.Warn("Failed to create .gitignore", zap.Error(gitErr))
	}

	timestamp := time.Now().Format(TimestampFormat)
	archivePath := filepath.Join(backupDir, timestamp+ArchiveSuffix)
	if err := createArchive(archivePath, stagingDir, filesToArchive); err != nil {
		return nil, fmt.Errorf("failed to create archive: %w", err)
	}
	result.ArchivePath = archivePath

	// Rotate manifests: current -> prev, then write new current
	manifestPath := filepath.Join(backupDir, ManifestFile)
	if _, statErr := os.Stat(manifestPath); statErr == nil {
		if renameErr := os.Rename(manifestPath, filepath.Join(backupDir, ManifestPrevFile)); renameErr != nil {
			logger.Warn("Failed to rotate previous manifest", zap.Error(renameErr))
		}
	}
	if err := writeManifest(manifestPath, newManifest); err != nil {
		return nil, fmt.Errorf("failed to write manifest: %w", err)
	}

	appendLog(filepath.Join(backupDir, LogFile), result, timestamp)

	// ═══════════════════════════════════════════════════════════════════
	// EVALUATE: Report results
	// ═══════════════════════════════════════════════════════════════════

	if archiveInfo, statErr := os.Stat(archivePath); statErr == nil {
		logger.Info("Archive created",
			zap.String("path", archivePath),
			zap.Int64("size_bytes", archiveInfo.Size()))
	}

	return result, nil
}

// collectSource copies files matching the source pattern to the staging directory.
// Returns the number of files collected. Errors are logged and gracefully skipped.
func collectSource(logger otelzap.LoggerWithCtx, src ChatSource, stagingDir string) int {
	info, err := os.Stat(src.Path)
	if err != nil {
		return 0
	}

	subdir := filepath.Join(stagingDir, src.Name)
	if mkErr := os.MkdirAll(subdir, BackupDirPerm); mkErr != nil {
		logger.Warn("Failed to create staging subdir",
			zap.String("tool", src.Name),
			zap.Error(mkErr))
		return 0
	}

	if !info.IsDir() {
		// Single file (e.g., Aider history, Claude history.jsonl)
		if info.Size() == 0 {
			return 0
		}
		if copyFile(src.Path, filepath.Join(subdir, filepath.Base(src.Path))) != nil {
			return 0
		}
		return 1
	}

	// Directory: walk and copy files matching pattern
	count := 0
	walkErr := filepath.Walk(src.Path, func(path string, fInfo os.FileInfo, accessErr error) error {
		if accessErr != nil {
			// Cannot access this entry; skip it and continue walking.
			return nil //nolint:nilerr // Walk callback: skip inaccessible entries
		}
		if fInfo.IsDir() || fInfo.Size() == 0 {
			return nil
		}
		if src.Pattern != "*" {
			matched, matchErr := filepath.Match(src.Pattern, fInfo.Name())
			if matchErr != nil || !matched {
				return nil //nolint:nilerr // Walk callback: skip non-matching entries
			}
		}
		rel, relErr := filepath.Rel(src.Path, path)
		if relErr != nil {
			return nil //nolint:nilerr // Walk callback: skip entries with bad paths
		}
		dst := filepath.Join(subdir, rel)
		if mkErr := os.MkdirAll(filepath.Dir(dst), BackupDirPerm); mkErr != nil {
			return nil //nolint:nilerr // Walk callback: skip entries we can't stage
		}
		if copyFile(path, dst) == nil {
			count++
		}
		return nil
	})
	if walkErr != nil {
		logger.Debug("Walk encountered errors", zap.String("tool", src.Name), zap.Error(walkErr))
	}

	// Clean up empty subdirectory
	if count == 0 {
		_ = os.Remove(subdir)
	}

	return count
}

// copyFile copies src to dst. Returns nil on success.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, BackupFilePerm)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// generateManifest computes SHA-256 hashes for all non-empty files in a directory.
// Returns entries sorted by filename for deterministic output.
func generateManifest(dir string) ([]manifestEntry, error) {
	var entries []manifestEntry

	err := filepath.Walk(dir, func(path string, info os.FileInfo, accessErr error) error {
		if accessErr != nil {
			return nil //nolint:nilerr // Walk callback: skip inaccessible entries
		}
		if info.IsDir() || info.Size() == 0 {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil //nolint:nilerr // Walk callback: skip entries with bad paths
		}
		hash, hashErr := crypto.HashFile(path)
		if hashErr != nil {
			return nil //nolint:nilerr // Walk callback: skip unhashable files
		}
		entries = append(entries, manifestEntry{File: rel, Hash: hash})
		return nil
	})

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].File < entries[j].File
	})

	return entries, err
}

// loadManifest reads a sha256sum-format manifest file into a map[filename]hash.
// Returns an empty map if the file doesn't exist (first run).
func loadManifest(path string) map[string]string {
	m := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ManifestSeparator, 2)
		if len(parts) == 2 {
			m[parts[1]] = parts[0]
		}
	}

	return m
}

// diffManifests compares new manifest entries against a previous manifest map.
// Returns counts of new, changed, and unchanged files, plus the list of files to archive.
func diffManifests(newEntries []manifestEntry, prev map[string]string) (newFiles, changed, unchanged int, toArchive []string) {
	for _, entry := range newEntries {
		prevHash, exists := prev[entry.File]
		switch {
		case !exists:
			newFiles++
			toArchive = append(toArchive, entry.File)
		case prevHash != entry.Hash:
			changed++
			toArchive = append(toArchive, entry.File)
		default:
			unchanged++
		}
	}
	return newFiles, changed, unchanged, toArchive
}

// writeManifest writes manifest entries in sha256sum-compatible format.
func writeManifest(path string, entries []manifestEntry) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, BackupFilePerm)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, e := range entries {
		fmt.Fprintf(w, "%s%s%s\n", e.Hash, ManifestSeparator, e.File)
	}
	return w.Flush()
}

// createArchive creates a gzip-compressed tar archive containing the specified files.
// File paths in files are relative to baseDir.
func createArchive(archivePath, baseDir string, files []string) error {
	out, err := os.OpenFile(archivePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, BackupFilePerm)
	if err != nil {
		return err
	}
	defer out.Close()

	gzw := gzip.NewWriter(out)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	for _, relPath := range files {
		if err := addFileToTar(tw, baseDir, relPath); err != nil {
			return err
		}
	}

	return nil
}

// addFileToTar adds a single file to a tar writer.
func addFileToTar(tw *tar.Writer, baseDir, relPath string) error {
	absPath := filepath.Join(baseDir, relPath)
	info, err := os.Stat(absPath)
	if err != nil {
		return nil // skip missing files
	}

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return nil // skip unreadable files
	}
	header.Name = relPath

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header for %s: %w", relPath, err)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil // skip unreadable files
	}
	defer f.Close()

	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("failed to write file data for %s: %w", relPath, err)
	}

	return nil
}

// ensureGitignore creates the chats/.gitignore if it doesn't exist.
func ensureGitignore(repoRoot string) error {
	path := filepath.Join(repoRoot, GitignoreRelPath)
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, BackupDirPerm); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(GitignoreContent), BackupFilePerm)
}

// appendLog writes a summary line to the append-only backup log.
func appendLog(logPath string, result *BackupResult, timestamp string) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, BackupFilePerm)
	if err != nil {
		return
	}
	defer f.Close()

	archived := result.NewFiles + result.ChangedFiles
	fmt.Fprintf(f, "[%s] archived=%d new=%d changed=%d unchanged=%d path=%s\n",
		timestamp, archived, result.NewFiles, result.ChangedFiles,
		result.UnchangedFiles, result.ArchivePath)
}
