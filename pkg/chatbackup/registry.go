// pkg/chatbackup/registry.go
// Declarative registry of AI coding tools and their data locations
//
// RATIONALE: Instead of hardcoding paths in bash scripts, we declare
// each tool's data locations in Go. This is testable, extensible, and
// self-documenting. Adding a new tool = adding one entry to the registry.
//
// EVIDENCE: The prompts/.claude/skills/store-chats/scripts/backup-chats.sh
// covers 12 tools but in bash; session_backup.go covers only 2 (Claude, Codex).
// This registry consolidates and extends both.
//
// Sources:
//   - Claude Code: https://docs.anthropic.com/en/docs/claude-code
//   - Codex CLI: https://github.com/openai/codex
//   - VS Code: https://code.visualstudio.com/docs/getstarted/settings
//   - Windsurf: https://docs.codeium.com/windsurf
//   - Continue: https://docs.continue.dev/

package chatbackup

// DefaultToolRegistry returns the full list of AI tool sources to back up.
// Each entry declares where a tool stores its data and what to include/exclude.
//
// Design decision: We back up EVERYTHING that constitutes "AI context" -
// conversations, settings, memory files, project configs, MCP server configs.
// This enables the feedback loop described in the task: statistical analysis
// of prompt engineering and iterative improvement.
func DefaultToolRegistry() []ToolSource {
	return []ToolSource{
		// ─── Claude Code ───────────────────────────────────────────
		{
			Name:        "claude-code",
			Description: "Anthropic Claude Code CLI sessions, settings, and memory",
			Paths: []SourcePath{
				{
					Path:        "~/.claude/projects",
					Description: "Session transcripts, indexes, and per-project memory files",
					// No Includes filter — back up everything: *.jsonl, *.json,
					// memory/*.md (MEMORY.md, feedback_*.md, etc.), and any
					// future file types Claude Code adds to projects/
				},
				{
					Path:        "~/.claude/todos",
					Description: "Todo lists from coding sessions",
				},
				{
					Path:        "~/.claude/file-history",
					Description: "File modification history across sessions",
				},
				{
					Path:        "~/.claude/plans",
					Description: "Implementation plans from plan mode",
				},
				{
					Path:        "~/.claude/sessions",
					Description: "Active session data",
				},
				{
					Path:        "~/.claude/tasks",
					Description: "Task tracking data from coding sessions",
				},
				{
					Path:        "~/.claude/plugins",
					Description: "Installed plugin metadata and marketplace config",
				},
				{
					Path:        "~/.claude/backups",
					Description: "Claude Code internal backup data",
				},
				{
					Path:        "~/.claude/settings.json",
					Description: "User settings (permissions, allowed commands)",
				},
				{
					Path:        "~/.claude/settings.local.json",
					Description: "Local settings overrides (machine-specific)",
				},
				{
					Path:        "~/.claude/config.json",
					Description: "CLI configuration (model preferences, features)",
				},
				// NOTE: ~/.claude/.credentials.json is intentionally excluded
				// (listed in DefaultExcludes) — it contains auth secrets.
				{
					Path:        "~/.claude/history.jsonl",
					Description: "Command history across sessions",
				},
				{
					Path:        "~/.claude/ide",
					Description: "IDE integration state",
				},
				{
					Path:        "~/.claude/paste-cache",
					Description: "Paste cache for session continuity",
				},
			},
		},
		// ─── OpenAI Codex CLI ──────────────────────────────────────
		{
			Name:        "codex",
			Description: "OpenAI Codex CLI sessions, config, state databases, and memory",
			Paths: []SourcePath{
				{
					Path:        "~/.codex/sessions",
					Description: "Session transcripts and conversation data",
				},
				{
					Path:        "~/.codex/config.toml",
					Description: "Codex CLI configuration",
				},
				{
					Path:        "~/.codex/auth.json",
					Description: "Authentication state (tokens, not secrets)",
				},
				{
					Path:        "~/.codex/skills",
					Description: "Codex custom skills",
				},
				{
					Path:        "~/.codex/memories",
					Description: "Codex persistent memory across sessions",
				},
				{
					Path:        "~/.codex/shell_snapshots",
					Description: "Shell state snapshots",
				},
				{
					Path:        "~/.codex/session_index.jsonl",
					Description: "Session index for cross-referencing conversations",
				},
				{
					Path:        "~/.codex/version.json",
					Description: "Codex version metadata",
				},
				{
					Path:        "~/.codex",
					Includes:    []string{"state*.sqlite*", "logs*.sqlite*"},
					Description: "State and log databases (conversation history, metrics)",
				},
			},
		},
		// ─── VS Code / VSCodium ────────────────────────────────────
		{
			Name:        "vscode",
			Description: "VS Code user settings and extension state",
			Paths: []SourcePath{
				{
					Path:        "~/.config/Code/User/settings.json",
					Description: "VS Code user settings",
				},
				{
					Path:        "~/.config/Code/User/keybindings.json",
					Description: "VS Code keybindings",
				},
				{
					Path:        "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/tasks",
					Includes:    []string{"*.json"},
					Description: "Cline (Claude Dev) task history",
				},
				{
					Path:        "~/.config/Code/User/globalStorage/RooVeterinaryInc.roo-cline",
					Includes:    []string{"*.json"},
					Description: "Roo Code task history",
				},
				{
					Path:        "~/.config/Code/User/globalStorage/GitHub.copilot-chat",
					Description: "GitHub Copilot chat history",
				},
			},
		},
		// ─── Windsurf ──────────────────────────────────────────────
		{
			Name:        "windsurf",
			Description: "Windsurf IDE global storage and settings",
			Paths: []SourcePath{
				{
					Path:        "~/.config/Windsurf/User",
					Description: "Windsurf user state, settings, keybindings, and storage",
				},
			},
		},
		// ─── Cursor ────────────────────────────────────────────────
		{
			Name:        "cursor",
			Description: "Cursor IDE settings and chat history",
			Paths: []SourcePath{
				{
					Path:        "~/.config/Cursor/User/globalStorage",
					Includes:    []string{"state.vscdb"},
					Description: "Cursor global state database",
				},
				{
					Path:        "~/.config/Cursor/User/settings.json",
					Description: "Cursor user settings",
				},
			},
		},
		// ─── Continue ──────────────────────────────────────────────
		{
			Name:        "continue",
			Description: "Continue IDE extension sessions and config",
			Paths: []SourcePath{
				{
					Path:        "~/.continue/sessions",
					Includes:    []string{"*.json"},
					Description: "Continue session history",
				},
				{
					Path:        "~/.continue/config.json",
					Description: "Continue configuration",
				},
			},
		},
		// ─── Amazon Q Developer ────────────────────────────────────
		{
			Name:        "amazon-q",
			Description: "Amazon Q Developer (formerly CodeWhisperer) chat history",
			Paths: []SourcePath{
				{
					Path:        "~/.aws/amazonq/history",
					Includes:    []string{"*.json"},
					Description: "Amazon Q chat history",
				},
			},
		},
		// ─── Aider ─────────────────────────────────────────────────
		{
			Name:        "aider",
			Description: "Aider AI coding assistant chat history",
			Paths: []SourcePath{
				{
					Path:        "~/.aider.chat.history.md",
					Description: "Aider global chat history",
				},
			},
		},
		// ─── OpenClaw ──────────────────────────────────────────────
		{
			Name:        "openclaw",
			Description: "OpenClaw self-hosted AI assistant config and sessions",
			Paths: []SourcePath{
				{
					Path:        "~/.openclaw/openclaw.json",
					Description: "OpenClaw configuration file",
				},
				{
					Path:        "~/.openclaw/config.yaml",
					Description: "OpenClaw main config (YAML format)",
				},
				{
					Path:        "~/.openclaw/.env",
					Description: "OpenClaw environment variables (API keys, secrets)",
				},
				{
					Path:        "~/.openclaw/workspace/skills",
					Description: "OpenClaw custom skills",
				},
				{
					Path:        "~/.openclaw/sessions",
					Includes:    []string{"*.json", "*.jsonl"},
					Description: "OpenClaw session transcripts",
				},
			},
		},
		// ─── Gemini CLI ────────────────────────────────────────────
		{
			Name:        "gemini-cli",
			Description: "Google Gemini CLI agent chat history, config, and session data",
			Paths: []SourcePath{
				{
					Path:        "~/.gemini/history",
					Description: "Gemini CLI conversation history",
				},
				{
					Path:        "~/.gemini/tmp",
					Includes:    []string{"shell_history", "*/shell_history", "*/chats/*", "*/checkpoints/*"},
					Description: "Session checkpoints, shell history, and chat transcripts",
				},
				{
					Path:        "~/.gemini/google_accounts.json",
					Description: "Google account association metadata",
				},
				// NOTE: ~/.gemini/oauth_creds.json is intentionally excluded
				// (listed in DefaultExcludes) — it contains OAuth secrets.
			},
		},
		// ─── ChatGPT Desktop (Third-Party) ────────────────────────
		// Multiple third-party ChatGPT desktop apps exist for Linux
		// We cover the most common ones (lencx/ChatGPT, electron-based)
		{
			Name:        "chatgpt-desktop",
			Description: "ChatGPT desktop app (third-party) chat history",
			Paths: []SourcePath{
				{
					Path:        "~/.config/ChatGPT",
					Description: "ChatGPT desktop app config and state",
				},
				{
					Path:        "~/.local/share/ChatGPT",
					Description: "ChatGPT desktop app data storage",
				},
			},
		},
		// ─── Gemini Desktop (Third-Party) ─────────────────────────
		{
			Name:        "gemini-desktop",
			Description: "Gemini desktop app (third-party) chat history",
			Paths: []SourcePath{
				{
					Path:        "~/.config/gemini-desktop",
					Description: "Gemini desktop app config and state",
				},
				{
					Path:        "~/.local/share/gemini-desktop",
					Description: "Gemini desktop app data storage",
				},
			},
		},
		// ─── Codex Archives ────────────────────────────────────────
		// Extended coverage for Codex session archives and logs
		{
			Name:        "codex-archives",
			Description: "OpenAI Codex archived sessions and exported data",
			Paths: []SourcePath{
				{
					Path:        "~/.codex/archives",
					Description: "Archived Codex sessions",
				},
				{
					Path:        "~/.codex/exports",
					Description: "Exported Codex data",
				},
			},
		},
	}
}

// ProjectContextPatterns returns file patterns to scan for in ExtraScanDirs.
// These are project-level AI context files that live alongside code.
//
// RATIONALE: CLAUDE.md, AGENTS.md, project-level .claude/ dirs contain
// critical AI context. Backing these up enables reconstructing the full
// AI interaction context for any project.
func ProjectContextPatterns() []string {
	return []string{
		"CLAUDE.md",
		"AGENTS.md",
		"QUICK-FACTS.md",
		"MEMORY.md",
		"memory.md",
		"MEMORY.mds",
		"memory.mds",
		".claude",
	}
}

// DefaultExcludes returns patterns that should always be excluded from backups.
// These are caches, telemetry, and temporary files that waste space.
func DefaultExcludes() []string {
	return []string{
		// Claude Code caches and telemetry (not valuable for recovery)
		".claude/downloads",
		".claude/statsig",
		".claude/telemetry",
		".claude/cache",
		".claude/debug",
		".claude/shell-snapshots",
		".claude/session-env",
		".claude/.credentials.json",
		".claude/stats-cache.json",
		".claude/mcp-needs-auth-cache.json",
		// Codex temporary files and caches
		".codex/tmp",
		".codex/log",
		".codex/models_cache.json",
		".codex/.personality_migration",
		// Gemini sensitive credentials (must NOT be backed up)
		".gemini/oauth_creds.json",
		// General exclusions
		"*.tmp",
		"*.log",
		"node_modules",
		".git",
		"__pycache__",
		// Git worktrees inside .claude (agent worktrees, not user data)
		"worktrees",
	}
}
