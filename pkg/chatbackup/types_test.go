package chatbackup

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ═══════════════════════════════════════════════════════════════════════════
// RetentionPolicy Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestDefaultRetentionPolicy_Values(t *testing.T) {
	policy := DefaultRetentionPolicy()

	assert.Equal(t, DefaultKeepWithin, policy.KeepWithin,
		"KeepWithin should match constant")
	assert.Equal(t, DefaultKeepHourly, policy.KeepHourly,
		"KeepHourly should match constant")
	assert.Equal(t, DefaultKeepDaily, policy.KeepDaily,
		"KeepDaily should match constant")
	assert.Equal(t, DefaultKeepWeekly, policy.KeepWeekly,
		"KeepWeekly should match constant")
	assert.Equal(t, DefaultKeepMonthly, policy.KeepMonthly,
		"KeepMonthly should match constant")
}

func TestDefaultRetentionPolicy_SensibleDefaults(t *testing.T) {
	policy := DefaultRetentionPolicy()

	// RATIONALE: Retention should be generous enough to recover from mistakes
	// but not so generous it wastes disk space
	assert.NotEmpty(t, policy.KeepWithin,
		"KeepWithin must not be empty")
	assert.Greater(t, policy.KeepHourly, 0,
		"KeepHourly must be positive")
	assert.Greater(t, policy.KeepDaily, 0,
		"KeepDaily must be positive")
	assert.Greater(t, policy.KeepWeekly, 0,
		"KeepWeekly must be positive")
	assert.Greater(t, policy.KeepMonthly, 0,
		"KeepMonthly must be positive")
}

// ═══════════════════════════════════════════════════════════════════════════
// BackupConfig Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestDefaultBackupConfig_Values(t *testing.T) {
	config := DefaultBackupConfig()

	assert.Equal(t, []string{"/opt"}, config.ExtraScanDirs,
		"ExtraScanDirs should default to /opt")
	assert.Equal(t, DefaultRetentionPolicy(), config.Retention,
		"Retention should use default policy")
	assert.False(t, config.DryRun,
		"DryRun should default to false")
	assert.False(t, config.Verbose,
		"Verbose should default to false")
}

func TestDefaultBackupConfig_ExtraScanDirs(t *testing.T) {
	config := DefaultBackupConfig()

	// RATIONALE: /opt is where Eos deploys projects with CLAUDE.md
	assert.Contains(t, config.ExtraScanDirs, "/opt",
		"default scan dirs must include /opt")
}

// ═══════════════════════════════════════════════════════════════════════════
// ScheduleConfig Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestDefaultScheduleConfig_Values(t *testing.T) {
	config := DefaultScheduleConfig()

	assert.Equal(t, DefaultBackupCron, config.BackupCron,
		"BackupCron should match constant")
	assert.Equal(t, DefaultPruneCron, config.PruneCron,
		"PruneCron should match constant")
	assert.Equal(t, DefaultBackupConfig(), config.BackupConfig,
		"BackupConfig should use defaults")
}

// ═══════════════════════════════════════════════════════════════════════════
// BackupStatus Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestBackupStatus_ZeroValue(t *testing.T) {
	status := BackupStatus{}

	// Zero value should be safe to use
	assert.Empty(t, status.LastAttempt)
	assert.Empty(t, status.LastRunState)
	assert.Empty(t, status.LastSuccess)
	assert.Empty(t, status.LastFailure)
	assert.Empty(t, status.LastError)
	assert.Empty(t, status.LastSnapshotID)
	assert.Equal(t, int64(0), status.BytesAdded)
	assert.Equal(t, 0, status.TotalSnapshots)
	assert.Equal(t, 0, status.SuccessCount)
	assert.Equal(t, 0, status.FailureCount)
	assert.Equal(t, 0, status.PathsBackedUpCount)
	assert.Equal(t, 0, status.PathsSkippedCount)
}

// ═══════════════════════════════════════════════════════════════════════════
// BackupResult Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestBackupResult_ZeroValue(t *testing.T) {
	result := BackupResult{}

	// Zero value should be safe to use
	assert.Empty(t, result.SnapshotID)
	assert.Nil(t, result.PathsBackedUp)
	assert.Nil(t, result.ToolsFound)
}
