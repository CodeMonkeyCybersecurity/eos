// pkg/chatarchive/defaults.go

package chatarchive

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

var userHomeDir = os.UserHomeDir

// DefaultSources returns platform-aware default source directories for
// chat transcript discovery. These cover Claude Code, Codex, OpenClaw,
// Windsurf, and Cursor session directories.
func DefaultSources() []string {
	return []string{
		"~/.claude",
		"~/.openclaw/agents/main/sessions",
		"~/.codex",
		"~/.windsurf",
		"~/.cursor",
		"~/Dev",
		"~/dev",
	}
}

// DefaultDest returns the platform-aware default destination directory.
func DefaultDest() string {
	homeDir, err := userHomeDir()
	if err != nil {
		return filepath.Join(".", "chat-archive")
	}
	return defaultDestForPlatform(runtime.GOOS, homeDir, os.Getenv("LOCALAPPDATA"), os.Getenv("XDG_DATA_HOME"))
}

func defaultDestForPlatform(goos, homeDir, localAppData, xdgDataHome string) string {
	switch goos {
	case "windows":
		base := localAppData
		if base == "" {
			base = filepath.Join(homeDir, "AppData", "Local")
		}
		return filepath.Join(base, shared.EosID, "chat-archive")
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", shared.EosID, "chat-archive")
	default:
		base := xdgDataHome
		if base == "" {
			base = filepath.Join(homeDir, ".local", "share")
		}
		return filepath.Join(base, shared.EosID, "chat-archive")
	}
}

// ExpandSources expands ~ in all source paths for compatibility with
// existing callers and tests. Prefer ResolveOptions for new code.
func ExpandSources(sources []string) []string {
	expanded := make([]string, 0, len(sources))
	for _, source := range sources {
		expanded = append(expanded, parse.ExpandHome(source))
	}
	return expanded
}
