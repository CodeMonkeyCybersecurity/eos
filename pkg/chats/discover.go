package chats

// discover.go — Chat source discovery for AI coding tools.
//
// Supports: Claude Code, Windsurf, Cursor, Codex CLI, Cline, Roo Code,
// GitHub Copilot, Aider, Amazon Q, Continue.dev.

import (
	"os"
	"path/filepath"
	"regexp"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ChatSource defines where an AI tool stores its chat data.
type ChatSource struct {
	// Name is a slug identifier used as the staging subdirectory (e.g., "claude-code").
	Name string
	// Path is the absolute directory or file path to scan.
	Path string
	// Pattern is the glob pattern to match files (e.g., "*.jsonl", "state.vscdb", "*").
	Pattern string
}

// DiscoveredSource is a ChatSource found on disk with file metadata.
type DiscoveredSource struct {
	Name      string
	Path      string
	FileCount int
	TotalSize int64
}

// nonAlphanumericRe replaces non-alphanumeric characters for project path encoding.
var nonAlphanumericRe = regexp.MustCompile(`[^a-zA-Z0-9]`)

// EncodeProjectPath converts a filesystem path to Claude Code's encoded format.
// Replaces non-alphanumeric characters with hyphens and strips leading hyphens.
// Example: /opt/eos -> opt-eos
func EncodeProjectPath(path string) string {
	encoded := nonAlphanumericRe.ReplaceAllString(path, "-")
	for len(encoded) > 0 && encoded[0] == '-' {
		encoded = encoded[1:]
	}
	return encoded
}

// DefaultSources returns the standard set of AI tool chat locations.
// homeDir is the user's home directory, configDir is the platform config directory
// (XDG_CONFIG_HOME on Linux, Library/Application Support on macOS), and repoRoot
// is the current git repository root.
func DefaultSources(homeDir, configDir, repoRoot string) []ChatSource {
	encoded := EncodeProjectPath(repoRoot)
	return []ChatSource{
		{
			Name:    "claude-code",
			Path:    filepath.Join(homeDir, ".claude", "projects", encoded, "sessions"),
			Pattern: "*.jsonl",
		},
		{
			Name:    "claude-code-all",
			Path:    filepath.Join(homeDir, ".claude", "projects"),
			Pattern: "*.jsonl",
		},
		{
			Name:    "claude-code-index",
			Path:    filepath.Join(homeDir, ".claude", "projects", encoded),
			Pattern: "sessions-index.json",
		},
		{
			Name:    "claude-code-history",
			Path:    filepath.Join(homeDir, ".claude", "history.jsonl"),
			Pattern: "*",
		},
		{
			Name:    "windsurf",
			Path:    filepath.Join(configDir, "Windsurf", "User", "globalStorage"),
			Pattern: "*",
		},
		{
			Name:    "cursor",
			Path:    filepath.Join(configDir, "Cursor", "User", "globalStorage"),
			Pattern: "state.vscdb",
		},
		{
			Name:    "codex",
			Path:    filepath.Join(homeDir, ".codex", "sessions"),
			Pattern: "*.jsonl",
		},
		{
			Name:    "cline",
			Path:    filepath.Join(configDir, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "tasks"),
			Pattern: "*.json",
		},
		{
			Name:    "roo-code",
			Path:    filepath.Join(configDir, "Code", "User", "globalStorage", "RooVeterinaryInc.roo-cline"),
			Pattern: "*.json",
		},
		{
			Name:    "copilot",
			Path:    filepath.Join(configDir, "Code", "User", "globalStorage", "GitHub.copilot-chat"),
			Pattern: "*",
		},
		{
			Name:    "aider",
			Path:    filepath.Join(repoRoot, ".aider.chat.history.md"),
			Pattern: "*",
		},
		{
			Name:    "amazon-q",
			Path:    filepath.Join(homeDir, ".aws", "amazonq", "history"),
			Pattern: "*.json",
		},
		{
			Name:    "continue",
			Path:    filepath.Join(homeDir, ".continue", "sessions"),
			Pattern: "*.json",
		},
	}
}

// Discover checks which chat sources exist and returns metadata for each.
// Non-existent or empty sources are silently skipped.
func Discover(rc *eos_io.RuntimeContext, sources []ChatSource) []DiscoveredSource {
	logger := otelzap.Ctx(rc.Ctx)
	discovered := make([]DiscoveredSource, 0, len(sources))

	for _, src := range sources {
		info, err := os.Stat(src.Path)
		if err != nil {
			logger.Debug("Source not found",
				zap.String("tool", src.Name),
				zap.String("path", src.Path))
			continue
		}

		var count int
		var totalSize int64

		if !info.IsDir() {
			// Single file (e.g., Aider history, Claude history.jsonl)
			if info.Size() > 0 {
				count = 1
				totalSize = info.Size()
			}
		} else {
			count, totalSize = countMatchingFiles(src.Path, src.Pattern)
		}

		if count == 0 {
			continue
		}

		logger.Debug("Discovered source",
			zap.String("tool", src.Name),
			zap.Int("files", count),
			zap.Int64("bytes", totalSize))

		discovered = append(discovered, DiscoveredSource{
			Name:      src.Name,
			Path:      src.Path,
			FileCount: count,
			TotalSize: totalSize,
		})
	}

	return discovered
}

// countMatchingFiles walks a directory and counts non-empty files matching a glob pattern.
func countMatchingFiles(dir, pattern string) (int, int64) {
	var count int
	var totalSize int64

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, accessErr error) error { //nolint:errcheck // best-effort walk
		if accessErr != nil {
			return nil //nolint:nilerr // Walk callback: skip inaccessible entries
		}
		if info.IsDir() || info.Size() == 0 {
			return nil
		}
		if pattern != "*" {
			matched, matchErr := filepath.Match(pattern, info.Name())
			if matchErr != nil || !matched {
				return nil //nolint:nilerr // Walk callback: skip non-matching entries
			}
		}
		count++
		totalSize += info.Size()
		return nil
	})

	return count, totalSize
}
