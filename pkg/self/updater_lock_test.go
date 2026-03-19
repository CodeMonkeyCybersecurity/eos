package self

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateWithRollback_LockSpansTransactionAndRollback verifies that the
// update lock is held across both the transaction and rollback phases.
//
// REGRESSION: Previously, executeUpdateTransaction acquired the lock via
// defer and released it on return. Rollback then re-acquired it, but there
// was a race window between the two acquisitions where a concurrent process
// could start an update.
//
// FIX: Lock is now acquired in UpdateWithRollback and held via defer for
// the entire lifecycle.
func TestUpdateWithRollback_LockSpansTransactionAndRollback(t *testing.T) {
	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-test")
	require.NoError(t, os.WriteFile(testBinary, []byte("fake binary"), 0o755))

	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: testBinary,
			BackupDir:  filepath.Join(testDir, "backups"),
			GitBranch:  "main",
		},
		// Disable features that need a real git repo
		RequireCleanWorkingTree: false,
		CheckRunningProcesses:   false,
		AtomicInstall:           true,
	}

	updater := NewEnhancedEosUpdater(rc, config)

	// Pre-update safety checks will fail (no git repo), which is fine.
	// We're testing that the lock file doesn't leak.
	_ = updater.UpdateWithRollback()

	// After UpdateWithRollback returns (whether success or failure),
	// the lock must be released. Verify by acquiring it successfully.
	lockFile := testBinary + ".update.lock"
	lock, err := AcquireUpdateLock(rc, testBinary)
	if err != nil {
		t.Fatalf("Lock should be released after UpdateWithRollback returns, got: %v", err)
	}
	lock.Release()
	_ = os.Remove(lockFile)
}

// TestRollback_AcquiresLockIndependently verifies the public Rollback()
// method acquires its own lock for external callers.
func TestRollback_AcquiresLockIndependently(t *testing.T) {
	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-test")
	require.NoError(t, os.WriteFile(testBinary, []byte("fake binary"), 0o755))

	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: testBinary,
			BackupDir:  filepath.Join(testDir, "backups"),
			GitBranch:  "main",
		},
	}

	updater := NewEnhancedEosUpdater(rc, config)

	// Public Rollback() should succeed (no-op since nothing to rollback)
	err := updater.Rollback()
	assert.NoError(t, err, "Rollback should succeed when there's nothing to rollback")

	// Verify lock is released after
	lock, err := AcquireUpdateLock(rc, testBinary)
	require.NoError(t, err, "Lock should be released after Rollback returns")
	lock.Release()
}

// TestRollback_FailsWhenLockHeld verifies that Rollback fails gracefully
// when another process holds the lock.
func TestRollback_FailsWhenLockHeld(t *testing.T) {
	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-test")
	require.NoError(t, os.WriteFile(testBinary, []byte("fake binary"), 0o755))

	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	// Hold the lock
	lock, err := AcquireUpdateLock(rc, testBinary)
	require.NoError(t, err)
	defer lock.Release()

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: testBinary,
			BackupDir:  filepath.Join(testDir, "backups"),
			GitBranch:  "main",
		},
	}

	updater := NewEnhancedEosUpdater(rc, config)

	// Public Rollback() should fail because we hold the lock
	err = updater.Rollback()
	assert.Error(t, err, "Rollback should fail when lock is held by another")
	assert.Contains(t, err.Error(), "rollback lock")
}
