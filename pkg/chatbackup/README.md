# pkg/chatbackup

*Last Updated: 2026-03-01*

Machine-wide backup of AI coding tool conversations, settings, and context files.

## Purpose

Provides hourly, deduplicated, encrypted backup of all AI coding assistant data across the system. This enables:

- **Audit trail**: Complete record of all AI interactions
- **Context preservation**: MEMORY.md, CLAUDE.md, settings survive reinstalls
- **Feedback loop**: Statistical analysis of prompt engineering effectiveness
- **Disaster recovery**: Restore any point-in-time snapshot

## Supported Tools

| Tool | Data Location | What's Backed Up |
|------|--------------|-----------------|
| Claude Code | `~/.claude/` | Sessions (JSONL), settings, memory, todos, plans |
| OpenAI Codex | `~/.codex/` | Sessions, config, skills, shell snapshots |
| VS Code | `~/.config/Code/` | Settings, keybindings, Cline/Roo/Copilot history |
| Windsurf | `~/.config/Windsurf/` | Global storage, settings |
| Cursor | `~/.config/Cursor/` | Global state, settings |
| Continue | `~/.continue/` | Sessions, config |
| Amazon Q | `~/.aws/amazonq/` | Chat history |
| Aider | `~/.aider.*` | Chat history |

Additionally scans `/opt/` for project-level context: `CLAUDE.md`, `AGENTS.md`, `QUICK-FACTS.md`, `.claude/` directories.

## Usage

```bash
# One-time setup (creates restic repo, password, cron)
sudo eos backup chats --setup

# Manual backup run
eos backup chats

# Show what would be backed up (dry run)
eos backup chats --dry-run

# Prune old snapshots per retention policy
eos backup chats --prune

# List snapshots
eos backup chats --list
```

## Architecture

Follows Assess/Intervene/Evaluate pattern:

- `constants.go` - Single source of truth for paths, permissions, timeouts
- `types.go` - Configuration and result types
- `registry.go` - Declarative registry of AI tools and their data locations
- `backup.go` - Core backup logic (discover paths, run restic, update status)
- `setup.go` - Setup and scheduling (init repo, generate password, configure cron)

## Observability

### Structured Logs

All operations emit structured logs with key fields (`user`, `home_dir`, `path_count`, `tools_found`, `snapshot_id`, `bytes_added`, `duration`) for machine parsing.

### Status File

After each run, status is written atomically to:

`~/.eos/restic/chat-archive-status.json`

Example:

```json
{
  "last_success": "2026-03-01T12:00:00Z",
  "last_failure": "",
  "last_snapshot_id": "abc123",
  "bytes_added": 1024,
  "success_count": 42,
  "failure_count": 0,
  "first_backup": "2026-02-20T11:00:00Z",
  "tools_found": ["claude-code", "codex"]
}
```

### Monitoring and Alerting

- Alert when `last_success` is older than 24 hours.
- Alert when `failure_count` increases between checks.
- Track `bytes_added` trend for unusual spikes or sudden drops.
- Track `tools_found` changes to detect missing tool data after migrations.

## Testing and CI

- Unit tests: `go test ./pkg/chatbackup/... ./cmd/backup/...`
- Integration tests (real restic): `go test -tags=integration ./pkg/chatbackup/...`
- E2E smoke: `go test -tags=e2e_smoke ./test/e2e/smoke/...`

CI wiring:

- Unit lane enforces coverage threshold from `test/ci/suites.yaml`.
- Integration lane runs `pkg/chatbackup` integration tests and installs `restic` when missing.
- E2E smoke includes `backup chats --dry-run` command stability validation.

## Adding a New Tool

Add an entry to `DefaultToolRegistry()` in `registry.go`:

```go
{
    Name:        "my-tool",
    Description: "My AI Tool chat history",
    Paths: []SourcePath{
        {
            Path:        "~/.my-tool/sessions",
            Includes:    []string{"*.json"},
            Description: "Session transcripts",
        },
    },
},
```
