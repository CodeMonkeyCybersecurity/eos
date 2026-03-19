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
	UniqueFiles  int    // Number of unique files copied (or would be copied)
	Duplicates   int    // Number of duplicate files detected
	Skipped      int    // Number of files skipped (already in manifest)
	ManifestPath string // Path to the written manifest (empty on dry-run)
}

// Archive discovers, deduplicates, and copies chat transcripts into dest.
// It is idempotent: an existing manifest is loaded and its hashes are
// used to avoid re-copying already-archived files.
func Archive(rc *eos_io.RuntimeContext, opts Options) (*Result, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting chat archive",
		zap.Strings("sources", opts.Sources),
		zap.String("dest", opts.Dest),
		zap.Bool("dry_run", opts.DryRun))

	// ASSESS: create destination directory
	if !opts.DryRun {
		if err := os.MkdirAll(opts.Dest, shared.ServiceDirPerm); err != nil {
			return nil, fmt.Errorf("create destination dir %s: %w", opts.Dest, err)
		}
	}

	// Load existing manifest for idempotent merge
	mPath := ManifestPath(opts.Dest)
	existing, err := ReadManifest(mPath)
	if err != nil {
		logger.Warn("Could not read existing manifest, starting fresh",
			zap.String("path", mPath),
			zap.Error(err))
	}
	byHash := ExistingHashes(existing)

	// ASSESS: discover transcript files
	files, err := DiscoverTranscriptFiles(rc, opts.Sources, opts.Dest)
	if err != nil {
		return nil, fmt.Errorf("discover transcripts: %w", err)
	}
	logger.Info("Discovered candidate files", zap.Int("count", len(files)))

	// INTERVENE: hash, deduplicate, copy
	var newEntries []Entry
	result := &Result{}

	for _, src := range files {
		hash, size, err := FileSHA256(src)
		if err != nil {
			logger.Debug("Skipping file (hash error)",
				zap.String("path", src),
				zap.Error(err))
			continue
		}
		if size == 0 {
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
		if firstDest, ok := byHash[hash]; ok {
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
		destFile := filepath.Join(opts.Dest, fmt.Sprintf("%s-%s%s", hash[:12], slug, ext))
		entry.DestPath = destFile
		entry.Copied = true

		if !opts.DryRun {
			if err := copyFile(src, destFile); err != nil {
				return nil, fmt.Errorf("copy %s -> %s: %w", src, destFile, err)
			}
		}

		byHash[hash] = destFile
		result.UniqueFiles++
		newEntries = append(newEntries, entry)
	}

	// EVALUATE: write merged manifest
	if !opts.DryRun {
		manifest := MergeEntries(existing, newEntries)
		manifest.Sources = opts.Sources
		manifest.DestDir = opts.Dest
		if err := WriteManifest(mPath, manifest); err != nil {
			return nil, fmt.Errorf("write manifest: %w", err)
		}
		result.ManifestPath = mPath
	}

	logger.Info("Chat archive complete",
		zap.Int("unique_copied", result.UniqueFiles),
		zap.Int("duplicates", result.Duplicates),
		zap.Bool("dry_run", opts.DryRun))

	return result, nil
}

// copyFile copies src to dst with fsync for durability.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}
	return out.Sync()
}
