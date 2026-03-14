# pkg/chats

*Last Updated: 2026-03-14*

Incremental backup of AI coding tool chat histories with SHA-256 deduplication.

## Purpose

Discovers chat data from AI coding tools (Claude Code, Windsurf, Cursor, Codex CLI,
Cline, Roo Code, GitHub Copilot, Aider, Amazon Q, Continue.dev) and creates
deduplicated tar.gz archives in `chats/backups/` relative to the repo root.

## Key Functions

- `DefaultSources(homeDir, configDir, repoRoot)` - Returns the registry of known AI tool data locations
- `Discover(rc, sources)` - Checks which sources exist on disk and returns file counts/sizes
- `RunBackup(rc, config)` - Full Assess/Intervene/Evaluate backup pipeline
- `EncodeProjectPath(path)` - Converts filesystem paths to Claude Code's encoded format

## Deduplication

Uses SHA-256 manifest comparison (sha256sum-compatible format). On each run:
1. Collects matching files to a staging directory
2. Computes SHA-256 hashes for all staged files
3. Compares against the previous manifest by filename
4. Archives only new or changed files
5. Rotates the manifest (current -> prev, new -> current)

## Usage

```bash
eos backup chats            # Discover and create incremental backup
eos backup chats --dry-run  # Preview without archiving
```
