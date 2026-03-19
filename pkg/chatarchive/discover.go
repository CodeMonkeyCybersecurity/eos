// pkg/chatarchive/discover.go

package chatarchive

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// jsonValidationBufSize is the maximum bytes read from a .json file
// to check for chat-like structure. Bounded to prevent OOM on large files.
const jsonValidationBufSize = 4096

// skipDirs are directory names skipped during recursive walks.
var skipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"target":       {},
	"vendor":       {},
	".cache":       {},
	"outputs":      {},
	"dist":         {},
	"build":        {},
}

// DiscoverTranscriptFiles walks the given roots and returns file paths
// that look like chat transcripts. The dest directory and known archive
// locations are excluded to prevent self-referencing.
//
// All path comparisons use forward-slash normalisation via filepath.ToSlash
// so pattern matching works identically on Windows, macOS, and Linux.
func DiscoverTranscriptFiles(rc *eos_io.RuntimeContext, roots []string, dest string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	var out []string
	seen := make(map[string]struct{})
	skippedSymlinks := 0
	unreadableEntries := 0

	// Normalise dest for cross-platform comparison
	destNorm := normalise(filepath.Clean(dest))

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			logger.Warn("Skipping source directory",
				zap.String("root", root),
				zap.Error(err))
			continue
		}

		err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				unreadableEntries++
				logger.Debug("Skipping unreadable path",
					zap.String("path", path),
					zap.Error(err))
				return nil // skip unreadable entries
			}

			cleanPath := filepath.Clean(path)
			normPath := normalise(cleanPath)

			if d.Type()&os.ModeSymlink != 0 {
				skippedSymlinks++
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip destination directory
			if normPath == destNorm || strings.HasPrefix(normPath, destNorm+"/") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip known archive directories
			if d.IsDir() && isExcludedArchiveDir(normPath) {
				return filepath.SkipDir
			}

			// Skip common non-interesting directories
			if d.IsDir() {
				if _, skip := skipDirs[strings.ToLower(d.Name())]; skip {
					return filepath.SkipDir
				}
				return nil
			}

			if isCandidate(normPath, cleanPath) {
				if _, ok := seen[cleanPath]; !ok {
					seen[cleanPath] = struct{}{}
					out = append(out, cleanPath)
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", root, err)
		}
	}

	sort.Strings(out)
	logger.Info("Transcript discovery complete",
		zap.Int("files_found", len(out)),
		zap.Int("roots_scanned", len(roots)),
		zap.Int("skipped_symlinks", skippedSymlinks),
		zap.Int("unreadable_entries", unreadableEntries))
	return out, nil
}

// normalise converts a path to lowercase forward-slash form for
// cross-platform pattern matching.
func normalise(path string) string {
	return strings.ToLower(filepath.ToSlash(path))
}

// isExcludedArchiveDir checks if a normalised path is a known
// self-archive directory that should be skipped.
func isExcludedArchiveDir(normPath string) bool {
	return strings.Contains(normPath, "/dev/eos/outputs/chat-archive") ||
		strings.Contains(normPath, "/desktop/conversationarchive")
}

// isCandidate determines if a file path looks like a chat transcript.
// normPath is the lowercase, forward-slash-normalised version for matching.
// osPath is the original OS path for file I/O operations.
func isCandidate(normPath, osPath string) bool {
	base := filepath.Base(normPath)

	// Strong path clues (using forward slashes for cross-platform matching)
	hasPathClue := strings.Contains(normPath, "/.openclaw/") ||
		strings.Contains(normPath, "/.claude/") ||
		strings.Contains(normPath, "/.codex/") ||
		strings.Contains(normPath, "/.windsurf/") ||
		strings.Contains(normPath, "/.cursor/") ||
		strings.Contains(normPath, "/sessions/") ||
		strings.Contains(normPath, "/transcripts/") ||
		strings.Contains(normPath, "/chats/") ||
		strings.Contains(normPath, "conversation")

	if base == "memory.md" {
		return true
	}
	if strings.HasSuffix(normPath, ".jsonl") {
		// Archive all JSONL under ~/Dev recursively
		if strings.Contains(normPath, "/dev/") {
			return true
		}
		return hasPathClue ||
			strings.Contains(base, "chat") ||
			strings.Contains(base, "session") ||
			strings.Contains(base, "conversation") ||
			strings.Contains(base, "transcript")
	}
	if strings.HasSuffix(normPath, ".chat") {
		return true
	}
	if strings.HasSuffix(normPath, ".html") {
		return strings.Contains(base, "chat") ||
			strings.Contains(base, "conversation") ||
			strings.Contains(base, "transcript")
	}
	if strings.HasSuffix(normPath, ".json") {
		if !hasPathClue &&
			!strings.Contains(base, "chat") &&
			!strings.Contains(base, "conversation") &&
			!strings.Contains(base, "session") &&
			!strings.Contains(base, "transcript") {
			return false
		}
		return isJSONTranscript(osPath)
	}
	return false
}

// isJSONTranscript reads the first jsonValidationBufSize bytes of a
// JSON file and checks for chat-like structure indicators.
// Bounded read prevents OOM on large files.
func isJSONTranscript(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, jsonValidationBufSize)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}
	h := strings.ToLower(string(buf[:n]))

	hasMessages := strings.Contains(h, "\"messages\"")
	hasRole := strings.Contains(h, "\"role\"")
	hasContent := strings.Contains(h, "\"content\"")
	hasConversation := strings.Contains(h, "\"conversation\"")

	return (hasMessages && (hasRole || hasContent)) ||
		(hasConversation && hasContent)
}
