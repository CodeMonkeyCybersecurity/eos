// pkg/chatarchive/archive.go
//
// Chat transcript archival: discover, deduplicate, and copy AI coding
// assistant chat histories into a local archive with manifest tracking.
// Cross-platform: uses filepath.ToSlash for all pattern matching.

package chatarchive

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Options configures the archive operation.
type Options struct {
	Sources []string // Expanded absolute source directories
	Dest    string   // Expanded absolute destination directory
	DryRun  bool     // If true, do not copy files or write manifest
}

// Result contains the outcome of an archive operation.
type Result struct {
	UniqueFiles           int           // Number of unique files copied (or would be copied)
	Duplicates            int           // Number of duplicate files detected within the current run
	Skipped               int           // Number of files already represented by the existing manifest
	EmptyFiles            int           // Number of empty candidate files ignored
	FailureCount          int           // Number of non-fatal file-level failures
	ManifestPath          string        // Path to the written manifest (empty on dry-run)
	RecoveredManifestPath string        // Corrupt manifest backup path if recovery was needed
	Duration              time.Duration // End-to-end runtime for the archive operation
	Failures              []FileFailure // Bounded list of failures for operator feedback
}

// FileFailure captures a non-fatal per-file failure encountered during archive.
type FileFailure struct {
	Path   string `json:"path"`
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
}

// Archive discovers, deduplicates, and copies chat transcripts into dest.
// It is idempotent: an existing manifest is loaded and its hashes are
// used to avoid re-copying already-archived files.
func Archive(rc *eos_io.RuntimeContext, opts Options) (*Result, error) {
	startedAt := time.Now()
	logger := otelzap.Ctx(rc.Ctx)
	resolvedOpts, err := ResolveOptions(opts)
	if err != nil {
		return nil, err
	}

	logger.Info("Starting chat archive",
		zap.Strings("sources", resolvedOpts.Sources),
		zap.String("dest", resolvedOpts.Dest),
		zap.Bool("dry_run", resolvedOpts.DryRun))

	result := &Result{}

	// ASSESS: create destination directory
	if !resolvedOpts.DryRun {
		if err := os.MkdirAll(resolvedOpts.Dest, shared.ServiceDirPerm); err != nil {
			return nil, fmt.Errorf("create destination dir %s: %w", resolvedOpts.Dest, err)
		}
	}

	// Load existing manifest for idempotent merge
	mPath := ManifestPath(resolvedOpts.Dest)
	existing, err := ReadManifest(mPath)
	if err != nil {
		recoveredPath, recoverErr := RecoverManifest(mPath)
		if recoverErr != nil {
			return nil, fmt.Errorf("read manifest: %w; recover manifest: %v", err, recoverErr)
		}
		result.RecoveredManifestPath = recoveredPath
		logger.Warn("Recovered corrupt manifest",
			zap.String("path", mPath),
			zap.String("recovered_path", recoveredPath),
			zap.Error(err))
	}
	existingHashes := ExistingHashes(existing)

	// ASSESS: discover transcript files
	files, err := DiscoverTranscriptFiles(rc, resolvedOpts.Sources, resolvedOpts.Dest)
	if err != nil {
		return nil, fmt.Errorf("discover transcripts: %w", err)
	}
	logger.Info("Discovered candidate files", zap.Int("count", len(files)))

	// INTERVENE: hash, deduplicate, copy
	var newEntries []Entry
	newHashes := make(map[string]string, len(files))

	for _, src := range files {
		hash, size, err := FileSHA256(src)
		if err != nil {
			logger.Warn("Skipping file after hash failure",
				zap.String("path", src),
				zap.Error(err))
			result.addFailure(src, "hash", err)
			continue
		}
		if size == 0 {
			result.EmptyFiles++
			continue
		}

		conversation := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
		entry := Entry{
			SourcePath:   src,
			SHA256:       hash,
			SizeBytes:    size,
			Conversation: conversation,
		}

		// Check existing manifest first (idempotent)
		if firstDest, ok := existingHashes[hash]; ok {
			entry.DuplicateOf = firstDest
			entry.DestPath = firstDest
			entry.Copied = false
			result.Skipped++
			continue
		}
		if firstDest, ok := newHashes[hash]; ok {
			entry.DuplicateOf = firstDest
			entry.DestPath = firstDest
			entry.Copied = false
			result.Duplicates++
			newEntries = append(newEntries, entry)
			continue
		}

		ext := filepath.Ext(src)
		if ext == "" {
			ext = ".bin"
		}
		slug := SanitizeName(conversation)
		if slug == "" {
			slug = "chat"
		}
		destFile := filepath.Join(resolvedOpts.Dest, fmt.Sprintf("%s-%s%s", hash[:12], slug, ext))
		entry.DestPath = destFile
		entry.Copied = true

		if !resolvedOpts.DryRun {
			if err := copyFile(src, destFile); err != nil {
				logger.Warn("Skipping file after copy failure",
					zap.String("source", src),
					zap.String("dest", destFile),
					zap.Error(err))
				result.addFailure(src, "copy", err)
				continue
			}
		}

		newHashes[hash] = destFile
		result.UniqueFiles++
		newEntries = append(newEntries, entry)
	}

	// EVALUATE: write merged manifest
	if !resolvedOpts.DryRun {
		manifest := MergeEntries(existing, newEntries)
		manifest.Sources = resolvedOpts.Sources
		manifest.DestDir = resolvedOpts.Dest
		if err := WriteManifest(mPath, manifest); err != nil {
			return nil, fmt.Errorf("write manifest: %w", err)
		}
		result.ManifestPath = mPath
	}

	result.Duration = time.Since(startedAt)
	logger.Info("Chat archive complete",
		zap.Int("unique_copied", result.UniqueFiles),
		zap.Int("duplicates", result.Duplicates),
		zap.Int("already_archived", result.Skipped),
		zap.Int("empty_files", result.EmptyFiles),
		zap.Int("failures", result.FailureCount),
		zap.Duration("duration", result.Duration),
		zap.Bool("dry_run", resolvedOpts.DryRun))

	return result, nil
}

func (r *Result) addFailure(path, stage string, err error) {
	r.FailureCount++
	if len(r.Failures) >= 20 {
		return
	}
	r.Failures = append(r.Failures, FileFailure{
		Path:   path,
		Stage:  stage,
		Reason: err.Error(),
	})
}

// copyFile copies src to dst with temp-file replacement and fsync for durability.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() { _ = in.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("create destination dir: %w", err)
	}

	out, err := os.CreateTemp(filepath.Dir(dst), ".chatarchive-*")
	if err != nil {
		return fmt.Errorf("create temp destination: %w", err)
	}
	tmpPath := out.Name()
	cleanup := true
	defer func() {
		_ = out.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}

	if info, err := os.Stat(src); err == nil {
		if chmodErr := out.Chmod(info.Mode().Perm()); chmodErr != nil {
			return fmt.Errorf("preserve permissions: %w", chmodErr)
		}
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("close temp destination: %w", err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("replace destination: %w", err)
	}

	dir, err := os.Open(filepath.Dir(dst))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	cleanup = false
	return nil
}
