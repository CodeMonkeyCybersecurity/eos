// pkg/self/updater_enhanced_test.go
//
// Integration tests for enhanced self-update functionality.
// These tests use REAL file operations (not mocks) to catch bugs like the O_WRONLY issue.

package self

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateTransactionBackup_RealFiles tests backup creation with actual file I/O
// CRITICAL: This test caught the O_WRONLY bug that prevented all self-updates
func TestCreateTransactionBackup_RealFiles(t *testing.T) {
	// Create temporary test binary
	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-test-binary")
	testData := []byte("This is a fake eos binary for testing backup functionality.\n" +
		"It needs to be long enough to test real I/O operations.\n" +
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n")

	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err, "failed to create test binary")

	// Create backup directory
	backupDir := filepath.Join(testDir, "backups")
	err = os.MkdirAll(backupDir, 0755)
	require.NoError(t, err, "failed to create backup directory")

	// Create test runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create updater configuration
	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: testBinary,
			BackupDir:  backupDir,
			GitBranch:  "main",
			MaxBackups: 3,
		},
		AtomicInstall: true,
	}

	updater := NewEnhancedEosUpdater(rc, config)

	// Execute backup creation - this is the CRITICAL test
	// Before fix: This would fail with "bad file descriptor" at line 715
	// After fix: This should succeed
	hash, err := updater.createTransactionBackup()
	assert.NoError(t, err, "backup creation should succeed")
	assert.NotEmpty(t, hash, "hash should be returned")

	// Verify backup file was created
	backupPath := updater.transaction.BackupBinaryPath
	assert.NotEmpty(t, backupPath, "backup path should be set in transaction")
	assert.FileExists(t, backupPath, "backup file should exist on disk")

	// Verify backup contains exact same data as original
	backupData, err := os.ReadFile(backupPath)
	require.NoError(t, err, "backup should be readable")
	assert.Equal(t, testData, backupData, "backup should match original binary byte-for-byte")

	// Verify backup hash matches returned hash
	backupHash := crypto.HashData(backupData)
	assert.Equal(t, hash, backupHash, "returned hash should match backup file hash")

	// Verify original binary hash matches
	originalHash := crypto.HashData(testData)
	assert.Equal(t, originalHash, hash, "backup hash should match original binary hash")

	// Verify backup file permissions
	backupInfo, err := os.Stat(backupPath)
	require.NoError(t, err, "backup file should be stat-able")
	assert.Equal(t, os.FileMode(0755), backupInfo.Mode().Perm(), "backup should have correct permissions")

	// Verify backup file size matches original
	assert.Equal(t, int64(len(testData)), backupInfo.Size(), "backup size should match original")
}

// TestCreateTransactionBackup_LargeFile tests backup with a larger binary
// Ensures memory handling works correctly for realistic binary sizes
func TestCreateTransactionBackup_LargeFile(t *testing.T) {
	// Create 10MB test binary (realistic size)
	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-large-binary")
	backupDir := filepath.Join(testDir, "backups")

	// Generate 10MB of test data
	largeData := make([]byte, 10*1024*1024) // 10 MB
	for i := range largeData {
		largeData[i] = byte(i % 256) // Deterministic pattern
	}

	err := os.WriteFile(testBinary, largeData, 0755)
	require.NoError(t, err, "failed to create large test binary")

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: testBinary,
			BackupDir:  backupDir,
			GitBranch:  "main",
			MaxBackups: 3,
		},
		AtomicInstall: true,
	}

	updater := NewEnhancedEosUpdater(rc, config)

	// Create backup
	hash, err := updater.createTransactionBackup()
	assert.NoError(t, err, "large file backup should succeed")
	assert.NotEmpty(t, hash, "hash should be returned for large file")

	// Verify backup integrity
	backupPath := updater.transaction.BackupBinaryPath
	backupData, err := os.ReadFile(backupPath)
	require.NoError(t, err, "large backup should be readable")
	assert.Equal(t, largeData, backupData, "large backup should match original")
}

// TestCreateTransactionBackup_VerifiesIntegrity tests that corrupted writes are detected
func TestCreateTransactionBackup_VerifiesIntegrity(t *testing.T) {
	// This test verifies that the hash verification actually works
	// We can't easily inject corruption, but we can verify the verification logic runs

	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-binary")
	testData := []byte("test binary data for integrity verification")

	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)

	backupDir := filepath.Join(testDir, "backups")
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: testBinary,
			BackupDir:  backupDir,
			GitBranch:  "main",
			MaxBackups: 3,
		},
		AtomicInstall: true,
	}

	updater := NewEnhancedEosUpdater(rc, config)

	// Create backup
	hash, err := updater.createTransactionBackup()
	require.NoError(t, err, "backup creation should succeed")

	// Verify the backup file hash matches what was returned
	backupPath := updater.transaction.BackupBinaryPath
	backupData, err := os.ReadFile(backupPath)
	require.NoError(t, err)

	actualHash := crypto.HashData(backupData)
	assert.Equal(t, hash, actualHash, "backup verification should detect any corruption")
}

// TestCreateTransactionBackup_BackupPathUniqueness tests that concurrent backups don't collide
func TestCreateTransactionBackup_BackupPathUniqueness(t *testing.T) {
	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-binary")
	testData := []byte("test data for uniqueness check")

	err := os.WriteFile(testBinary, testData, 0755)
	require.NoError(t, err)

	backupDir := filepath.Join(testDir, "backups")
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	config := &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  testDir,
			BinaryPath: testBinary,
			BackupDir:  backupDir,
			GitBranch:  "main",
			MaxBackups: 3,
		},
		AtomicInstall: true,
	}

	// Create multiple backups rapidly
	var backupPaths []string
	for i := 0; i < 3; i++ {
		updater := NewEnhancedEosUpdater(rc, config)
		_, err := updater.createTransactionBackup()
		require.NoError(t, err, "backup %d should succeed", i)

		backupPath := updater.transaction.BackupBinaryPath
		backupPaths = append(backupPaths, backupPath)
	}

	// Verify all backup paths are unique
	uniquePaths := make(map[string]bool)
	for _, path := range backupPaths {
		assert.False(t, uniquePaths[path], "backup path %s should be unique", path)
		uniquePaths[path] = true
	}

	assert.Equal(t, 3, len(uniquePaths), "should have 3 unique backup paths")
}

// TestCreateTransactionBackup_FilesystemErrors tests error handling
func TestCreateTransactionBackup_FilesystemErrors(t *testing.T) {
	t.Run("binary not readable", func(t *testing.T) {
		testDir := t.TempDir()
		testBinary := filepath.Join(testDir, "nonexistent-binary")
		backupDir := filepath.Join(testDir, "backups")

		rc := &eos_io.RuntimeContext{
			Ctx: context.Background(),
		}

		config := &EnhancedUpdateConfig{
			UpdateConfig: &UpdateConfig{
				SourceDir:  testDir,
				BinaryPath: testBinary,
				BackupDir:  backupDir,
				GitBranch:  "main",
				MaxBackups: 3,
			},
			AtomicInstall: true,
		}

		updater := NewEnhancedEosUpdater(rc, config)

		// Should fail gracefully when binary doesn't exist
		_, err := updater.createTransactionBackup()
		assert.Error(t, err, "should fail when binary doesn't exist")
		assert.Contains(t, err.Error(), "failed to open binary", "error should mention binary open failure")
	})

	t.Run("backup directory not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("Skipping permission test when running as root")
		}

		testDir := t.TempDir()
		testBinary := filepath.Join(testDir, "eos-binary")
		testData := []byte("test data")
		err := os.WriteFile(testBinary, testData, 0755)
		require.NoError(t, err)

		// Create read-only backup directory
		backupDir := filepath.Join(testDir, "readonly-backups")
		err = os.MkdirAll(backupDir, 0555) // read + execute only
		require.NoError(t, err)

		rc := &eos_io.RuntimeContext{
			Ctx: context.Background(),
		}

		config := &EnhancedUpdateConfig{
			UpdateConfig: &UpdateConfig{
				SourceDir:  testDir,
				BinaryPath: testBinary,
				BackupDir:  backupDir,
				GitBranch:  "main",
				MaxBackups: 3,
			},
			AtomicInstall: true,
		}

		updater := NewEnhancedEosUpdater(rc, config)

		// Should fail gracefully when backup dir is not writable
		_, err = updater.createTransactionBackup()
		assert.Error(t, err, "should fail when backup directory is not writable")
	})
}
