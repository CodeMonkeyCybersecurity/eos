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
					Includes:    []string{"*.jsonl", "*.json"},
					Description: "Session transcripts (JSONL) and session indexes",
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
					Path:     "~/.claude/settings.json",
					Includes: []string{"settings.json"},
					Description: "User settings including permissions, " +
						"allowed commands",
				},
				{
					Path:        "~/.claude/ide",
					Description: "IDE integration state",
				},
			},
		},
		// ─── Claude Code Project Memory ────────────────────────────
		// These are per-project memory files that persist context
		{
			Name:        "claude-code-memory",
			Description: "Per-project MEMORY.md files that persist AI context across sessions",
			Paths: []SourcePath{
				{
					Path:        "~/.claude/projects",
					Includes:    []string{"MEMORY.md"},
					Description: "Per-project memory files",
				},
			},
		},
		// ─── OpenAI Codex CLI ──────────────────────────────────────
		{
			Name:        "codex",
			Description: "OpenAI Codex CLI sessions, config, and state",
			Paths: []SourcePath{
				{
					Path:        "~/.codex/sessions",
					Includes:    []string{"*.jsonl"},
					Description: "Session transcripts",
				},
				{
					Path:        "~/.codex/config.toml",
					Description: "Codex CLI configuration",
				},
				{
					Path:        "~/.codex/skills",
					Description: "Codex custom skills",
				},
				{
					Path:        "~/.codex/shell_snapshots",
					Description: "Shell state snapshots",
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
					Path:        "~/.config/Windsurf/User/globalStorage",
					Description: "Windsurf global storage (chat history, state)",
				},
				{
					Path:        "~/.config/Windsurf/User/settings.json",
					Description: "Windsurf user settings",
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
			Description: "Google Gemini CLI agent chat history and config",
			Paths: []SourcePath{
				{
					Path:        "~/.gemini/tmp",
					Includes:    []string{"shell_history", "*/shell_history"},
					Description: "Gemini CLI shell history and session checkpoints",
				},
				{
					Path:        "~/.gemini/config",
					Description: "Gemini CLI configuration",
				},
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
		".claude",
	}
}

// DefaultExcludes returns patterns that should always be excluded from backups.
// These are caches, telemetry, and temporary files that waste space.
func DefaultExcludes() []string {
	return []string{
		// Claude Code caches and telemetry
		".claude/downloads",
		".claude/statsig",
		".claude/telemetry",
		".claude/cache",
		".claude/debug",
		".claude/shell-snapshots",
		// Codex temporary files
		".codex/tmp",
		".codex/log",
		".codex/models_cache.json",
		// General exclusions
		"*.tmp",
		"*.log",
		"node_modules",
		".git",
		"__pycache__",
	}
}
