// pkg/chatarchive/defaults.go

package chatarchive

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

var userHomeDir = os.UserHomeDir

// DefaultSources returns platform-aware default source directories for
// chat transcript discovery. These cover Claude Code, Codex, OpenClaw,
// Windsurf, and Cursor session directories.
func DefaultSources() []string {
	return defaultSourcesWithProvider(
		runtime.GOOS,
		userHomeDir,
		os.Getenv("APPDATA"),
		os.Getenv("LOCALAPPDATA"),
	)
}

// DefaultDest returns the platform-aware default destination directory.
func DefaultDest() string {
	return defaultDestWithProvider(runtime.GOOS, userHomeDir, os.Getenv("LOCALAPPDATA"), os.Getenv("XDG_DATA_HOME"))
}

func defaultSourcesForPlatform(goos, homeDir, appData, localAppData string) []string {
	common := []string{
		"~/.claude",
		"~/.openclaw/agents/main/sessions",
		"~/.codex",
		"~/.windsurf",
		"~/.cursor",
		"~/Dev",
		"~/dev",
	}

	var platformSpecific []string
	switch goos {
	case "windows":
		platformSpecific = append(platformSpecific,
			userProfileJoin(homeDir, "AppData", "Roaming", "Cursor"),
			userProfileJoin(homeDir, "AppData", "Roaming", "Windsurf"),
			userProfileJoin(homeDir, "AppData", "Local", "Cursor"),
			userProfileJoin(homeDir, "AppData", "Local", "Windsurf"),
		)
		if appData != "" {
			platformSpecific = append(platformSpecific,
				filepath.Join(appData, "Cursor"),
				filepath.Join(appData, "Windsurf"),
			)
		}
		if localAppData != "" {
			platformSpecific = append(platformSpecific,
				filepath.Join(localAppData, "Cursor"),
				filepath.Join(localAppData, "Windsurf"),
			)
		}
	case "darwin":
		platformSpecific = append(platformSpecific,
			userProfileJoin(homeDir, "Library", "Application Support", "Cursor"),
			userProfileJoin(homeDir, "Library", "Application Support", "Windsurf"),
		)
	default:
		platformSpecific = append(platformSpecific,
			"~/.config/Cursor",
			"~/.config/Windsurf",
		)
	}

	return uniqueNonEmptyStrings(append(common, platformSpecific...))
}

func defaultSourcesWithProvider(goos string, homeProvider func() (string, error), appData, localAppData string) []string {
	homeDir, err := homeProvider()
	if err != nil {
		homeDir = ""
	}
	return defaultSourcesForPlatform(goos, homeDir, appData, localAppData)
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
		expanded = append(expanded, expandUserPath(source))
	}
	return expanded
}

func expandUserPath(path string) string {
	home, err := userHomeDir()
	if err != nil {
		home = ""
	}
	return expandUserPathWithHome(path, home)
}

func expandUserPathWithHome(path, home string) string {
	trimmed := path
	switch {
	case trimmed == "~":
		if home == "" {
			return trimmed
		}
		return home
	case len(trimmed) >= 2 && trimmed[0] == '~' && (trimmed[1] == '/' || trimmed[1] == '\\'):
		if home == "" {
			return trimmed
		}
		relative := trimmed[2:]
		if relative == "" {
			return home
		}
		return filepath.Join(home, relative)
	default:
		return trimmed
	}
}

func defaultDestWithProvider(goos string, homeProvider func() (string, error), localAppData, xdgDataHome string) string {
	homeDir, err := homeProvider()
	if err != nil {
		return filepath.Join(".", "chat-archive")
	}
	return defaultDestForPlatform(goos, homeDir, localAppData, xdgDataHome)
}

func userProfileJoin(homeDir string, parts ...string) string {
	if homeDir == "" {
		return ""
	}
	all := append([]string{homeDir}, parts...)
	return filepath.Join(all...)
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
