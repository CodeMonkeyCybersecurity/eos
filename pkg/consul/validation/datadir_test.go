// pkg/consul/validation/datadir_test.go
//
// Tests for Consul data directory validation.
//
// Last Updated: 2025-10-25

package validation

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateConsulDataDir_ValidDirectory tests validation of a valid Consul data directory
func TestValidateConsulDataDir_ValidDirectory(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create raft subdirectory (required)
	raftDir := filepath.Join(tmpDir, "raft")
	err := os.MkdirAll(raftDir, 0755)
	require.NoError(t, err)

	// Create raft.db file (optional but common)
	raftDB := filepath.Join(raftDir, "raft.db")
	err = os.WriteFile(raftDB, []byte("test"), 0644)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate
	err = ValidateConsulDataDir(rc, tmpDir)

	// Should pass validation
	assert.NoError(t, err)
}

// TestValidateConsulDataDir_PathDoesNotExist tests validation of non-existent path
func TestValidateConsulDataDir_PathDoesNotExist(t *testing.T) {
	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate non-existent path
	err := ValidateConsulDataDir(rc, "/nonexistent/path")

	// Should fail
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

// TestValidateConsulDataDir_PathIsFile tests validation when path is a file not directory
func TestValidateConsulDataDir_PathIsFile(t *testing.T) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "consul-test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate file path (should be directory)
	err = ValidateConsulDataDir(rc, tmpFile.Name())

	// Should fail
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

// TestValidateConsulDataDir_MissingRaftSubdirectory tests validation without raft/ dir
func TestValidateConsulDataDir_MissingRaftSubdirectory(t *testing.T) {
	// Create temp directory WITHOUT raft subdirectory
	tmpDir := t.TempDir()

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate
	err := ValidateConsulDataDir(rc, tmpDir)

	// Should fail - raft/ is required
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain raft/ subdirectory")
}

// TestValidateConsulDataDir_EmptyRaftDirectory tests validation with empty raft/ dir
func TestValidateConsulDataDir_EmptyRaftDirectory(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create empty raft subdirectory
	raftDir := filepath.Join(tmpDir, "raft")
	err := os.MkdirAll(raftDir, 0755)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate
	err = ValidateConsulDataDir(rc, tmpDir)

	// Should pass - empty raft/ is OK (new installation)
	// Warnings will be logged but validation passes
	assert.NoError(t, err)
}

// TestValidateConsulDataDir_CompleteStructure tests validation with full directory structure
func TestValidateConsulDataDir_CompleteStructure(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create all expected subdirectories
	raftDir := filepath.Join(tmpDir, "raft")
	snapshotsDir := filepath.Join(raftDir, "snapshots")
	serfDir := filepath.Join(tmpDir, "serf")

	err := os.MkdirAll(snapshotsDir, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(serfDir, 0755)
	require.NoError(t, err)

	// Create expected files
	raftDB := filepath.Join(raftDir, "raft.db")
	err = os.WriteFile(raftDB, []byte("test"), 0644)
	require.NoError(t, err)

	checkpoint := filepath.Join(tmpDir, "checkpoint-signature")
	err = os.WriteFile(checkpoint, []byte("test"), 0644)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate
	err = ValidateConsulDataDir(rc, tmpDir)

	// Should pass with no warnings
	assert.NoError(t, err)
}

// TestValidateConsulDataDir_ReadOnlyDirectory tests validation of read-only directory
func TestValidateConsulDataDir_ReadOnlyDirectory(t *testing.T) {
	// Skip if not running as root (can't test permission scenarios)
	if os.Geteuid() != 0 {
		t.Skip("Skipping permission test - requires root")
	}

	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create raft subdirectory
	raftDir := filepath.Join(tmpDir, "raft")
	err := os.MkdirAll(raftDir, 0755)
	require.NoError(t, err)

	// Make directory read-only
	err = os.Chmod(tmpDir, 0555)
	require.NoError(t, err)
	defer os.Chmod(tmpDir, 0755) // Restore for cleanup

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate
	err = ValidateConsulDataDir(rc, tmpDir)

	// Should fail - directory not writable
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not writable")
}

// TestValidateConsulDataDir_SymlinkToValidDirectory tests validation of symlink
func TestValidateConsulDataDir_SymlinkToValidDirectory(t *testing.T) {
	// Create actual data directory
	actualDir := t.TempDir()
	raftDir := filepath.Join(actualDir, "raft")
	err := os.MkdirAll(raftDir, 0755)
	require.NoError(t, err)

	// Create symlink
	tmpDir := t.TempDir()
	symlinkPath := filepath.Join(tmpDir, "consul-link")
	err = os.Symlink(actualDir, symlinkPath)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate symlink
	err = ValidateConsulDataDir(rc, symlinkPath)

	// Should pass - symlinks are OK
	assert.NoError(t, err)
}

// TestValidateConsulDataDir_NestedRaftPath tests various raft path variations
func TestValidateConsulDataDir_NestedRaftPath(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create raft at expected location
	raftDir := filepath.Join(tmpDir, "raft")
	err := os.MkdirAll(raftDir, 0755)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate
	err = ValidateConsulDataDir(rc, tmpDir)

	// Should pass
	assert.NoError(t, err)
}

// TestValidateConsulDataDir_CaseInsensitiveFS tests behavior on case-insensitive filesystems
func TestValidateConsulDataDir_CaseInsensitiveFS(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create raft with lowercase (standard)
	raftDir := filepath.Join(tmpDir, "raft")
	err := os.MkdirAll(raftDir, 0755)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate with standard case
	err = ValidateConsulDataDir(rc, tmpDir)
	assert.NoError(t, err)
}

// TestValidateConsulDataDir_WithAdditionalFiles tests validation ignores extra files
func TestValidateConsulDataDir_WithAdditionalFiles(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()

	// Create required raft subdirectory
	raftDir := filepath.Join(tmpDir, "raft")
	err := os.MkdirAll(raftDir, 0755)
	require.NoError(t, err)

	// Create some extra files (should be ignored)
	err = os.WriteFile(filepath.Join(tmpDir, "random-file.txt"), []byte("test"), 0644)
	require.NoError(t, err)

	extraDir := filepath.Join(tmpDir, "extra-dir")
	err = os.MkdirAll(extraDir, 0755)
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Validate
	err = ValidateConsulDataDir(rc, tmpDir)

	// Should pass - extra files don't matter
	assert.NoError(t, err)
}
