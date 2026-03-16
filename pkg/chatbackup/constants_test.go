package chatbackup

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ═══════════════════════════════════════════════════════════════════════════
// Constants Tests - Verify values are sensible and permissions are secure
// ═══════════════════════════════════════════════════════════════════════════

func TestConstants_PathsNotEmpty(t *testing.T) {
	assert.NotEmpty(t, ResticRepoSubdir, "ResticRepoSubdir must not be empty")
	assert.NotEmpty(t, ResticPasswordSubdir, "ResticPasswordSubdir must not be empty")
	assert.NotEmpty(t, ResticStatusSubdir, "ResticStatusSubdir must not be empty")
	assert.NotEmpty(t, ResticLogSubdir, "ResticLogSubdir must not be empty")
	assert.NotEmpty(t, ResticLockSubdir, "ResticLockSubdir must not be empty")
	assert.NotEmpty(t, CronMarker, "CronMarker must not be empty")
}

func TestConstants_PathsSeparateFromSessionBackup(t *testing.T) {
	// RATIONALE: The new chat-archive paths must not collide with the
	// existing session_backup.go paths (.eos/restic/coding-sessions)
	assert.NotEqual(t, ".eos/restic/coding-sessions", ResticRepoSubdir,
		"must not collide with existing session backup repo")
	assert.NotEqual(t, ".eos/restic/password", ResticPasswordSubdir,
		"must not collide with existing session backup password")
}

func TestConstants_PermissionsNotWorldWritable(t *testing.T) {
	// SECURITY: P0 Rule #12 - all permissions must be documented and secure
	perms := []struct {
		name string
		perm os.FileMode
	}{
		{"RepoDirPerm", RepoDirPerm},
		{"ResticDirPerm", ResticDirPerm},
		{"PasswordFilePerm", PasswordFilePerm},
		{"StatusFilePerm", StatusFilePerm},
		{"LogFilePerm", LogFilePerm},
	}

	for _, p := range perms {
		// No permission should be world-writable (0002)
		assert.Equal(t, os.FileMode(0), p.perm&0002,
			"%s (%04o) must not be world-writable", p.name, p.perm)
	}
}

func TestConstants_PasswordPermIsReadOnly(t *testing.T) {
	// SECURITY: Password file must be owner read-only (0400)
	assert.Equal(t, os.FileMode(0400), PasswordFilePerm,
		"PasswordFilePerm must be 0400 (owner read-only)")
}

func TestConstants_RepoDirIsOwnerOnly(t *testing.T) {
	// SECURITY: Repository directory must be owner-only (0700)
	assert.Equal(t, os.FileMode(0700), RepoDirPerm,
		"RepoDirPerm must be 0700 (owner-only)")
}

func TestConstants_PasswordLength(t *testing.T) {
	// SECURITY: Password must have sufficient entropy
	// 32 URL-safe chars = ~190 bits, exceeds AES-128 (128 bits)
	assert.GreaterOrEqual(t, PasswordLength, 32,
		"PasswordLength must be at least 32 chars for adequate entropy")
}

func TestConstants_RetentionDefaults(t *testing.T) {
	assert.NotEmpty(t, DefaultKeepWithin)
	assert.Greater(t, DefaultKeepHourly, 0)
	assert.Greater(t, DefaultKeepDaily, 0)
	assert.Greater(t, DefaultKeepWeekly, 0)
	assert.Greater(t, DefaultKeepMonthly, 0)
}

func TestConstants_CronDefaults(t *testing.T) {
	assert.NotEmpty(t, DefaultBackupCron, "DefaultBackupCron must not be empty")
	assert.NotEmpty(t, DefaultPruneCron, "DefaultPruneCron must not be empty")

	// Backup and prune should not run at the same time
	assert.NotEqual(t, DefaultBackupCron, DefaultPruneCron,
		"backup and prune cron must differ to avoid lock contention")
}

func TestConstants_Timeouts(t *testing.T) {
	// Timeouts must be positive
	assert.Greater(t, BackupTimeout, time.Duration(0))
	assert.Greater(t, PruneTimeout, time.Duration(0))
	assert.Greater(t, ResticCommandTimeout, time.Duration(0))

	// Backup timeout should be less than prune timeout
	// (backups are smaller operations)
	assert.Less(t, BackupTimeout, PruneTimeout,
		"backup timeout should be less than prune timeout")
}

func TestConstants_Tags(t *testing.T) {
	assert.NotEmpty(t, BackupTag)
	assert.NotEmpty(t, AutoTag)
	assert.NotEqual(t, BackupTag, AutoTag,
		"backup and auto tags must be different")
}
