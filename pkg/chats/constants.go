// Package chats provides incremental backup of AI coding tool chat histories
// with SHA-256 deduplication. It discovers chat data from supported AI tools and
// creates deduplicated tar.gz archives in chats/backups/ relative to the repo root.
//
// constants.go — Chat backup infrastructure constants (SINGLE SOURCE OF TRUTH).
// CRITICAL: All chat backup paths, permissions, and format values
// MUST be defined here. Zero hardcoded values allowed (CLAUDE.md P0 rule #12).
package chats

import "os"

// Backup directory structure (relative to repo root)
const (
	// BackupSubdir is the backup output directory relative to repo root.
	// RATIONALE: Per-project storage keeps backups close to the code they reference.
	BackupSubdir = "chats/backups"

	// ManifestFile is the current SHA-256 manifest filename.
	// RATIONALE: sha256sum-compatible format enables manual verification.
	ManifestFile = "manifest.sha256"

	// ManifestPrevFile is the previous manifest for dedup comparison.
	// RATIONALE: Keeping one generation enables incremental diffing.
	ManifestPrevFile = "manifest.sha256.prev"

	// LogFile is the append-only backup log filename.
	// RATIONALE: Audit trail for backup operations.
	LogFile = "backup.log"

	// GitignoreRelPath is the .gitignore path relative to repo root.
	// RATIONALE: Chat backups may contain secrets referenced in conversations.
	GitignoreRelPath = "chats/.gitignore"

	// ArchiveSuffix is appended to the timestamp for archive naming.
	// Example: 2026-03-14-1430-chats.tar.gz
	ArchiveSuffix = "-chats.tar.gz"

	// TimestampFormat is the Go time format for archive timestamps.
	// Produces: YYYY-MM-DD-HHMM (e.g., 2026-03-14-1430)
	TimestampFormat = "2006-01-02-1504"

	// ManifestSeparator is the two-space separator used in sha256sum format.
	ManifestSeparator = "  "
)

// File permissions
const (
	// BackupDirPerm for the chats/backups/ directory.
	// RATIONALE: Standard directory permissions for local backup data.
	// SECURITY: Backup data is excluded from git by .gitignore.
	// THREAT MODEL: Low risk — local-only data, no remote exposure.
	BackupDirPerm = os.FileMode(0755)

	// BackupFilePerm for archive, manifest, and log files.
	// RATIONALE: Owner read/write, group/other read.
	// SECURITY: Archives may contain conversation data but are local-only.
	// THREAT MODEL: Protected by .gitignore from accidental commits.
	BackupFilePerm = os.FileMode(0644)
)

// GitignoreContent prevents chat backups from being committed to git.
const GitignoreContent = "# Chat backups are local data — never commit to git\n" +
	"# They may contain secrets referenced in conversations\n" +
	"*\n" +
	"!.gitignore\n"
