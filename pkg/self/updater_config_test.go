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

// TestNewEosUpdater_NoDefaultGitBranch verifies that NewEosUpdater does NOT
// default GitBranch to "main" when the caller doesn't set it.
//
// REGRESSION: Previously, NewEosUpdater defaulted GitBranch to "main". This
// undermined the branch safety contract: if a caller forgot to resolve the
// checked-out branch, the updater would silently target "main" instead of
// failing fast.
//
// FIX: GitBranch has no default. checkGitRepositoryState resolves and validates
// the branch at runtime.
func TestNewEosUpdater_NoDefaultGitBranch(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	config := &UpdateConfig{
		SourceDir:  "/opt/eos",
		BinaryPath: "/usr/local/bin/eos",
		// GitBranch intentionally not set
	}

	updater := NewEosUpdater(rc, config)

	assert.Empty(t, updater.config.GitBranch,
		"GitBranch should NOT have a default; callers must resolve the checked-out branch")
}

// TestCheckGitRepositoryState_ResolvesEmptyBranch verifies that when GitBranch
// is empty, checkGitRepositoryState resolves it from the checked-out branch.
func TestCheckGitRepositoryState_ResolvesEmptyBranch(t *testing.T) {
	repoDir := initUpdaterBranchTestRepo(t, "main")

	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  repoDir,
			BinaryPath: filepath.Join(t.TempDir(), "eos"),
			BackupDir:  t.TempDir(),
			GitBranch:  "", // Empty — should be resolved
		},
	}

	updater := NewEnhancedEosUpdater(rc, config)

	err := updater.checkGitRepositoryState()
	assert.NoError(t, err)
	assert.Equal(t, "main", updater.config.GitBranch,
		"Empty GitBranch should be resolved from checked-out branch")
}

// TestInstallBinaryAtomic_StreamsCopy verifies that installBinaryAtomic
// correctly streams the binary to the target without corrupting it.
func TestInstallBinaryAtomic_StreamsCopy(t *testing.T) {
	testDir := t.TempDir()
	targetBinary := filepath.Join(testDir, "eos-target")
	require.NoError(t, os.WriteFile(targetBinary, []byte("old binary"), 0o755))

	// Create source binary with known content
	sourceBinary := filepath.Join(testDir, "eos-new")
	sourceData := make([]byte, 1024*1024) // 1MB
	for i := range sourceData {
		sourceData[i] = byte(i % 251) // Prime-based pattern for corruption detection
	}
	require.NoError(t, os.WriteFile(sourceBinary, sourceData, 0o755))

	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: targetBinary,
			BackupDir:  filepath.Join(testDir, "backups"),
			GitBranch:  "main",
		},
		AtomicInstall: true,
	}

	updater := NewEnhancedEosUpdater(rc, config)

	err := updater.installBinaryAtomic(sourceBinary)
	assert.NoError(t, err)

	// Verify installed binary matches source exactly
	installed, err := os.ReadFile(targetBinary)
	require.NoError(t, err)
	assert.Equal(t, sourceData, installed,
		"Installed binary should match source byte-for-byte after streaming copy")
}

// TestInstallBinaryAtomic_CleansUpOnFailure verifies that a failed install
// does not leave a .new temp file behind.
func TestInstallBinaryAtomic_CleansUpOnFailure(t *testing.T) {
	testDir := t.TempDir()
	targetBinary := filepath.Join(testDir, "eos-target")
	require.NoError(t, os.WriteFile(targetBinary, []byte("old binary"), 0o755))

	// Source that doesn't exist — should fail
	nonexistentSource := filepath.Join(testDir, "does-not-exist")

	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: targetBinary,
			BackupDir:  filepath.Join(testDir, "backups"),
			GitBranch:  "main",
		},
		AtomicInstall: true,
	}

	updater := NewEnhancedEosUpdater(rc, config)

	err := updater.installBinaryAtomic(nonexistentSource)
	assert.Error(t, err)

	// Verify no .new temp file left behind
	tempFile := targetBinary + ".new"
	_, statErr := os.Stat(tempFile)
	assert.True(t, os.IsNotExist(statErr),
		".new temp file should not exist after failed install")
}
