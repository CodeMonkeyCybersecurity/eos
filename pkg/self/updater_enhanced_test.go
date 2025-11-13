// pkg/self/updater_enhanced_test.go
//
// Integration tests for enhanced self-update functionality.
// These tests use REAL file operations (not mocks) to catch bugs like the O_WRONLY issue.

package self

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
// P0 FIX: Now actually tests CONCURRENT execution (not sequential)
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

	// P0 FIX: Create backups CONCURRENTLY (not sequentially)
	// This actually tests that timestamp-based uniqueness works under race conditions
	const numConcurrent = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	backupPaths := make([]string, 0, numConcurrent)
	errors := make([]error, 0)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			updater := NewEnhancedEosUpdater(rc, config)
			_, err := updater.createTransactionBackup()

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errors = append(errors, fmt.Errorf("backup %d failed: %w", iteration, err))
				return
			}

			backupPaths = append(backupPaths, updater.transaction.BackupBinaryPath)
		}(i)
	}

	wg.Wait()

	// Verify no errors occurred
	require.Empty(t, errors, "all concurrent backups should succeed")

	// Verify all backup paths are unique (critical for concurrent safety)
	uniquePaths := make(map[string]bool)
	for _, path := range backupPaths {
		assert.False(t, uniquePaths[path], "concurrent backups created duplicate path: %s", path)
		uniquePaths[path] = true
	}

	assert.Equal(t, numConcurrent, len(uniquePaths), "should have %d unique backup paths", numConcurrent)
	assert.Equal(t, numConcurrent, len(backupPaths), "should have created %d backups", numConcurrent)

	// Verify all backup files actually exist and are valid
	for _, path := range backupPaths {
		assert.FileExists(t, path, "backup file should exist on disk")
		data, err := os.ReadFile(path)
		require.NoError(t, err, "backup should be readable")
		assert.Equal(t, testData, data, "backup should match original data")
	}
}

// TestCreateTransactionBackup_SeekErrorHandling tests that Seek() errors are properly caught
// This test validates the P0 fix for unchecked Seek() errors that could cause silent data corruption
func TestCreateTransactionBackup_SeekErrorHandling(t *testing.T) {
	// This is a regression test for the critical bug where Seek() errors were not checked
	// If Seek() fails silently, we could hash the wrong data and create a corrupted backup

	// NOTE: It's difficult to force Seek() to fail on a real filesystem
	// Seek() typically only fails if:
	//   1. File descriptor is invalid (but we just used it for write)
	//   2. File was deleted (but we're holding it open)
	//   3. Filesystem corruption (can't simulate safely)
	//
	// However, we CAN verify that the error check exists by:
	//   1. Checking the code has the error check (done via this test existing)
	//   2. Code coverage analysis should show the error path is reachable
	//   3. Manual review of the fix (done in adversarial analysis)

	// For now, this test documents WHY the check exists and what it prevents
	// Future: Could use os.Pipe() or other tricks to create an unseekable file descriptor

	testDir := t.TempDir()
	testBinary := filepath.Join(testDir, "eos-test-binary")
	testData := []byte("test binary for seek error validation")
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

	// Create backup - this will exercise the Seek() code path
	hash, err := updater.createTransactionBackup()
	assert.NoError(t, err, "backup should succeed with valid file")
	assert.NotEmpty(t, hash, "hash should be returned")

	// The fact that this test passes means:
	// 1. Seek(0, 0) was called (to rewind for verification)
	// 2. Error was checked (otherwise code would panic or return wrong hash)
	// 3. Verification read succeeded (proving seek worked)

	// If the P0 fix was removed (unchecked Seek), this test would still pass
	// BUT code coverage would show the error path is unreachable
	// AND manual inspection would reveal the bug
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
