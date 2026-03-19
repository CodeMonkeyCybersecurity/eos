// pkg/chatarchive/defaults.go

package chatarchive

import (
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"
)

// DefaultSources returns platform-aware default source directories for
// chat transcript discovery. These cover Claude Code, Codex, OpenClaw,
// Windsurf, and Cursor session directories.
func DefaultSources() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			"~/.claude",
			"~/.openclaw/agents/main/sessions",
			"~/.codex/sessions",
			"~/.windsurf",
			"~/.cursor",
			"~/Dev",
			"~/dev",
		}
	case "darwin":
		return []string{
			"~/.claude",
			"~/.openclaw/agents/main/sessions",
			"~/.codex/sessions",
			"~/.windsurf",
			"~/.cursor",
			"~/Dev",
			"~/dev",
		}
	default: // linux and others
		return []string{
			"~/.claude",
			"~/.openclaw/agents/main/sessions",
			"~/.codex/sessions",
			"~/.windsurf",
			"~/.cursor",
			"~/Dev",
			"~/dev",
		}
	}
}

// DefaultDest returns the platform-aware default destination directory.
func DefaultDest() string {
	return "~/Dev/eos/outputs/chat-archive"
}

// ExpandSources expands ~ in all source paths using the shared parse.ExpandHome.
func ExpandSources(sources []string) []string {
	expanded := make([]string, 0, len(sources))
	for _, s := range sources {
		expanded = append(expanded, parse.ExpandHome(s))
	}
	return expanded
}
