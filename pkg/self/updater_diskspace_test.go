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

// TestCheckDiskSpace_HandlesMissingBinary verifies that checkDiskSpace does
// not crash when the binary does not exist (first install scenario).
//
// REGRESSION: Previously, checkDiskSpace unconditionally called
// os.Stat(BinaryPath) without an os.IsNotExist guard. On first install,
// this returned an error and the update failed with a confusing message.
//
// FIX: checkDiskSpace now uses a conservative size estimate (150 MB) when
// the binary does not exist.
func TestCheckDiskSpace_HandlesMissingBinary(t *testing.T) {
	testDir := t.TempDir()
	nonexistentBinary := filepath.Join(testDir, "nonexistent-eos")

	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: nonexistentBinary,
			BackupDir:  filepath.Join(testDir, "backups"),
			GitBranch:  "main",
		},
	}

	updater := NewEnhancedEosUpdater(rc, config)

	// Should NOT return "failed to stat binary" error
	err := updater.checkDiskSpace()

	// The check may fail for other reasons (e.g., system.VerifyDiskSpace),
	// but it must NOT fail with the old "failed to stat binary" error.
	if err != nil {
		assert.NotContains(t, err.Error(), "failed to stat binary",
			"checkDiskSpace should handle missing binary gracefully, not fail on stat")
	}
}

// TestCheckDiskSpace_WorksWithExistingBinary verifies the normal path
// where the binary exists.
func TestCheckDiskSpace_WorksWithExistingBinary(t *testing.T) {
	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-test")
	require.NoError(t, os.WriteFile(testBinary, []byte("fake binary content"), 0o755))

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

	// Should succeed (unless disk is actually full, which is unlikely in tests)
	err := updater.checkDiskSpace()
	assert.NoError(t, err, "checkDiskSpace should work with existing binary")
}
