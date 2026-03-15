// pkg/chats/discover.go
// Discovery logic for AI chat tool data on the local filesystem.
//
// RATIONALE: Automatically detects which AI coding assistants have data
// on disk for a given user, enabling backup without manual configuration.
// Follows Assess pattern from CLAUDE.md.

package chats

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ToolInfo describes a discovered AI tool's data on disk
type ToolInfo struct {
	// Name is the tool identifier (e.g., "claude-code")
	Name string

	// DisplayName is the human-readable name (e.g., "Claude Code")
	DisplayName string

	// DataPath is the absolute path to the tool's data directory
	DataPath string

	// Excludes are paths to exclude from backup (relative to home)
	Excludes []string

	// Found indicates whether data was found on disk
	Found bool
}

// DiscoveryResult holds the result of scanning for AI tool data
type DiscoveryResult struct {
	// User is the username whose home directory was scanned
	User string

	// HomeDir is the absolute path to the user's home directory
	HomeDir string

	// Tools contains all discovered tools with data on disk
	Tools []ToolInfo

	// TotalFound is the count of tools with data found
	TotalFound int
}

// toolDefinition describes where to look for a tool's data
type toolDefinition struct {
	name        string
	displayName string
	relPath     string
	excludes    []string
}

// allTools defines all supported AI coding assistants
var allTools = []toolDefinition{
	{ToolClaudeCode, "Claude Code", ClaudeCodeRelPath, ClaudeCodeExcludes},
	{ToolCodex, "OpenAI Codex", CodexRelPath, nil},
	{ToolWindsurf, "Windsurf/Codeium", WindsurfRelPath, WindsurfExcludes},
	{ToolCursor, "Cursor", CursorRelPath, CursorExcludes},
	{ToolContinueDev, "Continue.dev", ContinueDevRelPath, ContinueDevExcludes},
	{ToolGitHubCopilot, "GitHub Copilot", GitHubCopilotRelPath, nil},
	{ToolGemini, "Gemini", GeminiRelPath, nil},
	{ToolAider, "Aider", AiderRelPath, nil},
}

// DiscoverChatData scans a user's home directory for AI tool data.
// If username is empty, it resolves the real user (SUDO_USER if running as root).
func DiscoverChatData(rc *eos_io.RuntimeContext, username string) (*DiscoveryResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	homeDir, resolvedUser, err := resolveUserHome(logger, username)
	if err != nil {
		return nil, err
	}

	logger.Info("Scanning for AI chat data",
		zap.String("user", resolvedUser),
		zap.String("home", homeDir))

	result := &DiscoveryResult{
		User:    resolvedUser,
		HomeDir: homeDir,
	}

	for _, tool := range allTools {
		absPath := filepath.Join(homeDir, tool.relPath)
		info, err := os.Stat(absPath)
		found := err == nil && info.IsDir()

		toolInfo := ToolInfo{
			Name:        tool.name,
			DisplayName: tool.displayName,
			DataPath:    absPath,
			Excludes:    tool.excludes,
			Found:       found,
		}

		if found {
			logger.Info("Found AI tool data",
				zap.String("tool", tool.displayName),
				zap.String("path", absPath))
			result.TotalFound++
		} else {
			logger.Debug("AI tool data not found",
				zap.String("tool", tool.displayName),
				zap.String("path", absPath))
		}

		result.Tools = append(result.Tools, toolInfo)
	}

	logger.Info("Chat data discovery complete",
		zap.Int("tools_found", result.TotalFound),
		zap.Int("tools_checked", len(allTools)))

	return result, nil
}

// FilterByTools filters discovery results to only include specified tools.
// If toolNames is empty, returns all found tools.
func FilterByTools(result *DiscoveryResult, toolNames []string) []ToolInfo {
	if len(toolNames) == 0 {
		var found []ToolInfo
		for _, t := range result.Tools {
			if t.Found {
				found = append(found, t)
			}
		}
		return found
	}

	nameSet := make(map[string]bool, len(toolNames))
	for _, n := range toolNames {
		nameSet[n] = true
	}

	var filtered []ToolInfo
	for _, t := range result.Tools {
		if t.Found && nameSet[t.Name] {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// resolveUserHome determines the home directory for the target user.
// When running as root via sudo, uses SUDO_USER to find the real user.
func resolveUserHome(logger otelzap.LoggerWithCtx, username string) (string, string, error) {
	if username != "" {
		u, err := user.Lookup(username)
		if err != nil {
			return "", "", fmt.Errorf("user %q not found: %w", username, err)
		}
		return u.HomeDir, username, nil
	}

	// When running as root via sudo, resolve the real user
	if os.Geteuid() == 0 {
		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser != "" && sudoUser != "root" {
			u, err := user.Lookup(sudoUser)
			if err != nil {
				logger.Warn("SUDO_USER lookup failed, falling back to root",
					zap.String("sudo_user", sudoUser),
					zap.Error(err))
			} else {
				logger.Info("Resolved real user from SUDO_USER",
					zap.String("user", sudoUser),
					zap.String("home", u.HomeDir))
				return u.HomeDir, sudoUser, nil
			}
		}
	}

	// Fall back to current user
	u, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("cannot determine current user: %w", err)
	}
	return u.HomeDir, u.Username, nil
}

// AvailableToolNames returns a list of all supported tool identifiers.
func AvailableToolNames() []string {
	names := make([]string, len(allTools))
	for i, t := range allTools {
		names[i] = t.name
	}
	return names
}
