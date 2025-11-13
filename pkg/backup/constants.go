// pkg/backup/constants.go
// Backup infrastructure constants - SINGLE SOURCE OF TRUTH
//
// CRITICAL: All backup-related paths, permissions, and configuration values
// MUST be defined here. Zero hardcoded values allowed (CLAUDE.md P0 rule #12).
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."

package backup

import "time"

// ═══════════════════════════════════════════════════════════════════════════
// File Paths - Backup Infrastructure
// ═══════════════════════════════════════════════════════════════════════════

const (
	// ConfigDir is the root directory for backup configuration
	// RATIONALE: Centralized configuration follows FHS 3.0 /etc/[service] pattern
	ConfigDir = "/etc/eos/backup"

	// ConfigFile is the main backup configuration file
	// RATIONALE: YAML format for human readability and multi-environment support
	ConfigFile = "/etc/eos/backup/config.yaml"

	// SecretsDir is the local directory for password fallback storage
	// RATIONALE: Separate from config for security (different permissions)
	// SECURITY: Vault-first, local fallback only when Vault unavailable
	SecretsDir = "/var/lib/eos/secrets/backup"

	// Quick backup repository path (user-specific)
	// NOTE: Uses ~ expansion at runtime via os.UserHomeDir()
	// RATIONALE: User-specific backups in home directory (standard pattern)
	QuickBackupRelativePath = ".eos/quick-backups"

	// StateDir for backup operation state tracking
	// RATIONALE: Persistent state for resumable operations (power loss recovery)
	StateDir = "/var/lib/eos/backup/state"

	// LogDir for backup operation logs
	// RATIONALE: Separate from systemd journal for long-term retention
	LogDir = "/var/log/eos/backup"
)

// ═══════════════════════════════════════════════════════════════════════════
// File Permissions - Security Critical
// ═══════════════════════════════════════════════════════════════════════════

const (
	// ConfigFilePerm is the permission for backup configuration files
	// RATIONALE: World-readable config (no secrets), owner writable
	// SECURITY: Configuration is not secret, passwords in Vault
	// THREAT MODEL: Prevents config tampering by non-root users
	ConfigFilePerm = 0644

	// ConfigDirPerm is the permission for backup configuration directory
	// RATIONALE: Standard directory permissions for /etc/[service]
	ConfigDirPerm = 0755

	// PasswordFilePerm is the permission for local password fallback files
	// RATIONALE: Owner read-only (root), no other access
	// SECURITY: Passwords are secrets, minimal access required
	// THREAT MODEL: Prevents password exposure to non-root users/processes
	// COMPLIANCE: PCI-DSS 8.2.1, SOC2 CC6.1 (restrict secret access)
	PasswordFilePerm = 0400

	// PasswordDirPerm is the permission for secrets directory
	// RATIONALE: Owner read/execute only for directory traversal
	// SECURITY: Directory must be traversable to read password files
	PasswordDirPerm = 0500

	// StateDirPerm is the permission for state directory
	// RATIONALE: Owner full control, no group/other access
	// SECURITY: State files may contain sensitive paths/metadata
	StateDirPerm = 0700

	// StateFilePerm is the permission for state files
	// RATIONALE: Owner read/write, no other access
	StateFilePerm = 0600

	// TempPasswordFilePerm is the permission for temporary password files
	// RATIONALE: Owner read-only during restic execution
	// SECURITY: Temporary files deleted immediately after use
	// THREAT MODEL: Prevents race conditions where attacker reads temp file
	TempPasswordFilePerm = 0400
)

// ═══════════════════════════════════════════════════════════════════════════
// Vault Configuration
// ═══════════════════════════════════════════════════════════════════════════

const (
	// VaultPasswordPathPrefix is the Vault KV path prefix for backup passwords
	// RATIONALE: Namespaced under eos/ for multi-tenant Vault environments
	// Example: eos/backup/repositories/production -> password for "production" repo
	VaultPasswordPathPrefix = "eos/backup/repositories"

	// VaultPasswordKey is the key name for password within Vault secret
	// RATIONALE: Consistent key naming across all backup repositories
	VaultPasswordKey = "password"
)

// ═══════════════════════════════════════════════════════════════════════════
// Restic Configuration
// ═══════════════════════════════════════════════════════════════════════════

const (
	// ResticBinaryName is the expected name of the restic binary
	// RATIONALE: Standard package name across all distributions
	ResticBinaryName = "restic"

	// ResticMinVersion is the minimum supported restic version
	// RATIONALE: Restic 0.14.0+ required for repository format 2 (compression)
	// Reference: https://github.com/restic/restic/releases/tag/v0.14.0
	ResticMinVersion = "0.14.0"

	// ResticRepositoryVersion is the repository format version
	// RATIONALE: Version 2 enables compression (20-40% space savings)
	// Reference: https://restic.readthedocs.io/en/latest/repository_format.html
	ResticRepositoryVersion = "2"

	// ResticDefaultCacheDir is the default cache directory for restic
	// NOTE: Uses ~ expansion at runtime
	// RATIONALE: User-specific cache in home directory
	ResticDefaultCacheDir = "~/.cache/restic"
)

// ═══════════════════════════════════════════════════════════════════════════
// Retention Policy Defaults
// ═══════════════════════════════════════════════════════════════════════════

const (
	// DefaultKeepDaily is the default number of daily snapshots to retain
	// RATIONALE: 7 daily snapshots = 1 week of daily restore points
	// INDUSTRY STANDARD: AWS Backup, Azure Backup, Google Cloud Backup (7 days)
	DefaultKeepDaily = 7

	// DefaultKeepWeekly is the default number of weekly snapshots to retain
	// RATIONALE: 4 weekly snapshots = 1 month of weekly restore points
	// INDUSTRY STANDARD: 3-4 weeks standard across cloud providers
	DefaultKeepWeekly = 4

	// DefaultKeepMonthly is the default number of monthly snapshots to retain
	// RATIONALE: 12 monthly snapshots = 1 year of monthly restore points
	// INDUSTRY STANDARD: Annual retention for compliance (SOX, HIPAA, PCI-DSS)
	DefaultKeepMonthly = 12

	// DefaultKeepYearly is the default number of yearly snapshots to retain
	// RATIONALE: 5 yearly snapshots = long-term archival
	// COMPLIANCE: Some regulations require 7-year retention (adjust as needed)
	DefaultKeepYearly = 5
)

// ═══════════════════════════════════════════════════════════════════════════
// Operational Timeouts
// ═══════════════════════════════════════════════════════════════════════════

const (
	// DefaultBackupTimeout is the maximum time for a backup operation
	// RATIONALE: Large backups (1TB+) can take hours, but infinite is dangerous
	// ADJUSTABLE: Increase for very large datasets
	DefaultBackupTimeout = 24 * time.Hour

	// DefaultRestoreTimeout is the maximum time for a restore operation
	// RATIONALE: Restores are typically faster than backups (no compression)
	DefaultRestoreTimeout = 12 * time.Hour

	// DefaultPruneTimeout is the maximum time for a prune operation
	// RATIONALE: Pruning can be I/O intensive, especially on remote backends
	DefaultPruneTimeout = 6 * time.Hour

	// DefaultCheckTimeout is the maximum time for repository integrity check
	// RATIONALE: Integrity checks read entire repository (slow on large repos)
	DefaultCheckTimeout = 12 * time.Hour

	// DefaultLockTimeout is the maximum time to wait for repository lock
	// RATIONALE: Prevents deadlocks from crashed backup processes
	// REFERENCE: Restic default is 30 minutes, we use 15 for faster failure
	DefaultLockTimeout = 15 * time.Minute
)

// ═══════════════════════════════════════════════════════════════════════════
// Retry Configuration
// ═══════════════════════════════════════════════════════════════════════════

const (
	// DefaultMaxRetries is the maximum number of retries for transient failures
	// RATIONALE: Network glitches, temporary locks - retry is appropriate
	// NOTE: Deterministic errors (config, validation) should NOT retry
	DefaultMaxRetries = 3

	// DefaultRetryBackoff is the initial backoff duration between retries
	// RATIONALE: Exponential backoff starting at 5s (5s, 10s, 20s)
	DefaultRetryBackoff = 5 * time.Second

	// DefaultMaxRetryBackoff is the maximum backoff duration
	// RATIONALE: Cap exponential backoff at 2 minutes to avoid excessive delays
	DefaultMaxRetryBackoff = 2 * time.Minute
)

// ═══════════════════════════════════════════════════════════════════════════
// Quick Backup Configuration
// ═══════════════════════════════════════════════════════════════════════════

const (
	// QuickBackupRepositoryName is the repository name for quick backups
	// RATIONALE: Consistent naming for user-facing "eos backup ." command
	QuickBackupRepositoryName = "quick-backups"

	// QuickBackupPasswordLength is the length of generated passwords
	// RATIONALE: 32 characters = 256 bits entropy (sufficient for AES-256)
	// SECURITY: Cryptographically secure random generation via crypto.GeneratePassword
	QuickBackupPasswordLength = 32

	// QuickBackupTag is the tag applied to all quick backups
	// RATIONALE: Distinguishes quick backups from profile-based backups
	QuickBackupTag = "quick-backup"
)

// ═══════════════════════════════════════════════════════════════════════════
// Safety Limits
// ═══════════════════════════════════════════════════════════════════════════

var (
	// CriticalSystemPaths are paths that should NEVER be restored to without explicit --target
	// RATIONALE: Prevents catastrophic system destruction via "cd / && eos restore ."
	// SECURITY: Defense in depth - user must explicitly request dangerous operations
	// THREAT MODEL: Accidental restore to root destroys system (CVSS 8.2)
	CriticalSystemPaths = []string{
		"/",      // Root filesystem
		"/etc",   // System configuration
		"/usr",   // System binaries and libraries
		"/var",   // System state and logs
		"/boot",  // Bootloader and kernel
		"/home",  // All user home directories
		"/opt",   // Optional software
		"/root",  // Root user home directory
		"/bin",   // Essential binaries
		"/sbin",  // System binaries
		"/lib",   // Shared libraries
		"/lib64", // 64-bit shared libraries
	}
)

// ═══════════════════════════════════════════════════════════════════════════
// Hook Configuration
// ═══════════════════════════════════════════════════════════════════════════

const (
	// HookTimeout is the maximum time for a hook script to execute
	// RATIONALE: Prevents hung backups from infinite hook execution
	HookTimeout = 5 * time.Minute

	// HookMaxOutputSize is the maximum output size from hook scripts (bytes)
	// RATIONALE: Prevents memory exhaustion from hooks with infinite output
	HookMaxOutputSize = 1024 * 1024 // 1MB
)

// ═══════════════════════════════════════════════════════════════════════════
// Notification Configuration
// ═══════════════════════════════════════════════════════════════════════════

const (
	// DefaultNotificationTimeout is the maximum time to send a notification
	// RATIONALE: Prevents backup delays from slow notification endpoints
	DefaultNotificationTimeout = 30 * time.Second

	// DefaultNotificationRetries is the number of retries for failed notifications
	// RATIONALE: Notifications are non-critical, limit retries to avoid delays
	DefaultNotificationRetries = 2
)
