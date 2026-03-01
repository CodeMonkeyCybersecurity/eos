// pkg/chatbackup/constants.go
// Chat backup infrastructure constants - SINGLE SOURCE OF TRUTH
//
// CRITICAL: All chat backup-related paths, permissions, and configuration values
// MUST be defined here. Zero hardcoded values allowed (CLAUDE.md P0 rule #12).
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."

package chatbackup

import (
	"os"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// File Paths - Chat Backup Infrastructure
// ═══════════════════════════════════════════════════════════════════════════

const (
	// ResticRepoSubdir is the restic repository path relative to home directory
	// RATIONALE: Separate from general backup repos to avoid confusion
	ResticRepoSubdir = ".eos/restic/chat-archive"

	// ResticPasswordSubdir is the password file relative to home directory
	// RATIONALE: Reuse existing .eos/restic/ structure for consistency
	ResticPasswordSubdir = ".eos/restic/chat-archive-password"

	// ResticStatusSubdir is the status tracking file relative to home directory
	// RATIONALE: Machine-readable health metrics for monitoring/alerting
	ResticStatusSubdir = ".eos/restic/chat-archive-status.json"

	// ResticLogSubdir is the log file relative to home directory
	ResticLogSubdir = ".eos/restic/chat-archive.log"

	// ResticLockSubdir is the lock file relative to home directory
	// RATIONALE: flock prevents concurrent backup runs
	ResticLockSubdir = ".eos/restic/chat-archive.lock"

	// CronMarker is the identifier used to find/replace cron entries
	CronMarker = "eos-chat-archive"
)

// ═══════════════════════════════════════════════════════════════════════════
// File Permissions - Security Critical
// ═══════════════════════════════════════════════════════════════════════════

const (
	// RepoDirPerm is the permission for the restic repository directory
	// RATIONALE: Owner-only access to encrypted backup data
	// SECURITY: Prevents unauthorized access to backup repository
	// THREAT MODEL: Prevents backup data theft by other users
	RepoDirPerm = os.FileMode(0700)

	// ResticDirPerm is the permission for the .eos/restic/ directory
	// RATIONALE: Owner-only access to backup infrastructure
	// SECURITY: Contains password files and status data
	// THREAT MODEL: Prevents credential exposure via directory listing
	ResticDirPerm = os.FileMode(0700)

	// PasswordFilePerm is the permission for the repository password file
	// RATIONALE: Owner read-only to prevent password exposure via ps or /proc
	// SECURITY: Prevents password modification after creation
	// THREAT MODEL: Mitigates credential replacement attacks
	PasswordFilePerm = os.FileMode(0400)

	// StatusFilePerm is the permission for the status tracking file
	// RATIONALE: Owner read/write for status updates
	// SECURITY: Status contains no secrets, just timestamps and counts
	// THREAT MODEL: Low risk - health metrics only
	StatusFilePerm = os.FileMode(0644)

	// LogFilePerm is the permission for the log file
	// RATIONALE: Owner read/write, world read for debugging
	// SECURITY: Logs may contain paths but no secrets
	// THREAT MODEL: Information disclosure via paths is acceptable
	LogFilePerm = os.FileMode(0644)
)

// ═══════════════════════════════════════════════════════════════════════════
// Restic Configuration
// ═══════════════════════════════════════════════════════════════════════════

const (
	// PasswordLength is the number of characters for generated passwords
	// RATIONALE: 32 chars URL-safe = ~190 bits entropy (exceeds AES-128)
	PasswordLength = 32

	// BackupTag is the restic tag applied to all chat archive snapshots
	BackupTag = "chat-archive"

	// AutoTag marks snapshots created by automated/scheduled runs
	AutoTag = "auto"
)

// ═══════════════════════════════════════════════════════════════════════════
// Retention Policy Defaults
// ═══════════════════════════════════════════════════════════════════════════

const (
	// DefaultKeepWithin keeps ALL snapshots within this duration
	// RATIONALE: Fine-grained recovery for recent work (2 days)
	DefaultKeepWithin = "48h"

	// DefaultKeepHourly keeps N hourly snapshots after KeepWithin period
	// RATIONALE: Matches hourly backup schedule for 1 day of hourly granularity
	DefaultKeepHourly = 24

	// DefaultKeepDaily keeps N daily snapshots
	// RATIONALE: 7 days covers a work week of daily snapshots
	DefaultKeepDaily = 7

	// DefaultKeepWeekly keeps N weekly snapshots
	// RATIONALE: 4 weeks covers a month of weekly snapshots
	DefaultKeepWeekly = 4

	// DefaultKeepMonthly keeps N monthly snapshots
	// RATIONALE: 12 months covers a year of monthly snapshots
	DefaultKeepMonthly = 12
)

// ═══════════════════════════════════════════════════════════════════════════
// Scheduling
// ═══════════════════════════════════════════════════════════════════════════

const (
	// DefaultBackupCron is the default cron schedule (hourly at minute 0)
	DefaultBackupCron = "0 * * * *"

	// DefaultPruneCron is the default prune schedule (daily at 3:05am)
	// RATIONALE: Offset 5 minutes from backup to avoid lock contention
	DefaultPruneCron = "5 3 * * *"
)

// ═══════════════════════════════════════════════════════════════════════════
// Operational Timeouts
// ═══════════════════════════════════════════════════════════════════════════

const (
	// BackupTimeout is the maximum time allowed for a single backup run
	// RATIONALE: Chat data is typically <1GB; 10 minutes is generous
	BackupTimeout = 10 * time.Minute

	// PruneTimeout is the maximum time allowed for a prune operation
	// RATIONALE: Pruning large repos can take time
	PruneTimeout = 30 * time.Minute

	// ResticCommandTimeout is the timeout for restic metadata commands
	// RATIONALE: cat config, snapshots listing should be fast
	ResticCommandTimeout = 30 * time.Second
)
