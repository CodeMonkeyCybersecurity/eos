# pkg/chats

*Last Updated: 2026-03-14*

AI chat data discovery and backup for coding assistants.

## Purpose

Discovers and backs up conversation data from AI coding tools (Claude Code, OpenAI Codex, Windsurf, Cursor, Continue.dev, GitHub Copilot, Gemini, Aider) for data analysis, auditing, and preservation.

## Usage

```bash
# Back up all discovered AI chat data
eos backup chats

# Back up specific tools only
eos backup chats --tool claude-code --tool codex

# Dry run
eos backup chats --dry-run

# Specify user (default: auto-detects via SUDO_USER)
eos backup chats --user henry
```

## Package Structure

- `constants.go` - Tool identifiers, data paths, exclude patterns
- `discover.go` - Filesystem discovery of AI tool data
- `backup.go` - Restic backup orchestration (Assess/Intervene/Evaluate)

## Adding a New Tool

1. Add tool constant to `constants.go`
2. Add relative path constant to `constants.go`
3. Add exclude patterns if needed
4. Add entry to `allTools` slice in `discover.go`
