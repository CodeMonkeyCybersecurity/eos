// pkg/chats/constants.go
// Constants for AI chat tool discovery and backup.
//
// RATIONALE: Centralizes all AI tool data paths, excludes, and backup
// configuration in one place per CLAUDE.md P0 constants rule.

package chats

// Tool identifiers for AI coding assistants
const (
	ToolClaudeCode    = "claude-code"
	ToolCodex         = "codex"
	ToolWindsurf      = "windsurf"
	ToolCursor        = "cursor"
	ToolContinueDev   = "continue"
	ToolGitHubCopilot = "github-copilot"
	ToolGemini        = "gemini"
	ToolAider         = "aider"
)

// Relative paths from user home directory for each tool's data
const (
	// ClaudeCodeRelPath is the Claude Code data directory
	// Contains: projects/{path}/*.jsonl, todos/, file-history/, plans/
	ClaudeCodeRelPath = ".claude"

	// CodexRelPath is the OpenAI Codex CLI data directory
	// Contains: SQLite databases, sessions, memories, skills
	CodexRelPath = ".codex"

	// WindsurfRelPath is the Windsurf/Codeium data directory
	// Contains: code_tracker/, brain/, memories/, codemaps/
	WindsurfRelPath = ".codeium"

	// CursorRelPath is the Cursor IDE data directory
	CursorRelPath = ".cursor"

	// ContinueDevRelPath is the Continue.dev data directory
	ContinueDevRelPath = ".continue"

	// GitHubCopilotRelPath is the GitHub Copilot config directory
	GitHubCopilotRelPath = ".config/github-copilot"

	// GeminiRelPath is the Google Gemini CLI data directory
	GeminiRelPath = ".gemini"

	// AiderRelPath is the Aider chat history directory
	AiderRelPath = ".aider"
)

// Backup tag constants
const (
	// BackupTagPrefix is the prefix for all chat backup tags
	BackupTagPrefix = "chat-backup"

	// BackupTagTool is the tag key for the tool name
	BackupTagTool = "tool"
)

// ClaudeCodeExcludes are paths to exclude from Claude Code backups.
// These contain cache/telemetry data that is not useful for data analysis.
var ClaudeCodeExcludes = []string{
	".claude/downloads",
	".claude/statsig",
	".claude/telemetry",
	".claude/cache",
	".claude/.credentials.json",
}

// WindsurfExcludes are paths to exclude from Windsurf backups.
var WindsurfExcludes = []string{
	".codeium/windsurf/cache",
	".codeium/cache",
}

// CursorExcludes are paths to exclude from Cursor backups.
var CursorExcludes = []string{
	".cursor/extensions",
	".cursor/Cache",
	".cursor/CachedData",
	".cursor/CachedExtensions",
	".cursor/CachedExtensionVSIXs",
}

// ContinueDevExcludes are paths to exclude from Continue.dev backups.
var ContinueDevExcludes = []string{
	".continue/index",
	".continue/cache",
}
