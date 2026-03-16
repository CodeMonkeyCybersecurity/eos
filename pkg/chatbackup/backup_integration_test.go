//go:build integration

package chatbackup

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ═══════════════════════════════════════════════════════════════════════════
// Integration Tests - Require restic binary on PATH
// Run with: go test -tags integration ./pkg/chatbackup/...
// ═══════════════════════════════════════════════════════════════════════════

func requireRestic(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not installed, skipping integration test")
	}
}

func newTestRC(t *testing.T) *eos_io.RuntimeContext {
	t.Helper()
	return eos_io.NewContext(context.Background(), "test")
}

func TestIntegration_Setup_CreatesRepo(t *testing.T) {
	requireRestic(t)

	tmpDir := t.TempDir()

	// Create a fake home directory with Claude data
	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(claudeDir, "test-session.jsonl"),
		[]byte(`{"type":"user","message":"hello"}`+"\n"),
		0644))

	rc := newTestRC(t)

	// Override the user's home for this test
	config := ScheduleConfig{
		BackupConfig: BackupConfig{
			User:          "",
			HomeDir:       tmpDir,
			ExtraScanDirs: []string{},
			Retention:     DefaultRetentionPolicy(),
		},
		BackupCron: DefaultBackupCron,
		PruneCron:  DefaultPruneCron,
	}

	// We can't run the full Setup because it uses resolveHomeDir
	// Instead, test the individual steps

	// Test initRepo
	repoPath := filepath.Join(tmpDir, ResticRepoSubdir)
	passwordFile := filepath.Join(tmpDir, ResticPasswordSubdir)

	// Generate password
	err := generatePassword(passwordFile)
	require.NoError(t, err)

	// Verify password file exists with correct permissions
	info, err := os.Stat(passwordFile)
	require.NoError(t, err)
	assert.Equal(t, PasswordFilePerm, info.Mode().Perm(),
		"password file should have 0400 permissions")

	// Read password and verify length
	password, err := os.ReadFile(passwordFile)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(password), PasswordLength,
		"password should be at least %d characters", PasswordLength)

	// Test initRepo
	err = initRepo(rc, repoPath, passwordFile)
	require.NoError(t, err)

	// Verify repo initialized (idempotent check)
	err = checkRepoInitialized(rc.Ctx, repoPath, passwordFile)
	require.NoError(t, err, "repo should be initialized")

	// Test idempotent re-init
	err = initRepo(rc, repoPath, passwordFile)
	require.NoError(t, err, "re-init should succeed (idempotent)")

	_ = config // Use config to avoid lint
}

func TestIntegration_Backup_CreatesSnapshot(t *testing.T) {
	requireRestic(t)

	tmpDir := t.TempDir()

	// Create test data
	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(claudeDir, "session1.jsonl"),
		[]byte(`{"type":"user","message":"test message"}`+"\n"),
		0644))

	// Set up restic
	repoPath := filepath.Join(tmpDir, ResticRepoSubdir)
	passwordFile := filepath.Join(tmpDir, ResticPasswordSubdir)

	require.NoError(t, generatePassword(passwordFile))

	rc := newTestRC(t)
	require.NoError(t, initRepo(rc, repoPath, passwordFile))

	// Run backup directly (bypass resolveHomeDir)
	logger := newSilentLogger()
	registry := []ToolSource{
		{
			Name:        "claude-code",
			Description: "Test",
			Paths: []SourcePath{
				{
					Path:        "~/.claude/projects",
					Description: "Projects",
				},
			},
		},
	}

	paths, toolsFound, _ := discoverPaths(logger, registry, tmpDir)
	require.NotEmpty(t, paths, "should discover Claude data")
	require.Contains(t, toolsFound, "claude-code")

	result, err := runResticBackup(rc.Ctx, logger, repoPath, passwordFile, paths)
	require.NoError(t, err)

	assert.NotEmpty(t, result.SnapshotID, "should create a snapshot")
	assert.Greater(t, result.FilesNew, 0, "should have new files")
}

func TestIntegration_Backup_StatusFileUpdated(t *testing.T) {
	requireRestic(t)

	tmpDir := t.TempDir()

	// Create test data
	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(claudeDir, "session1.jsonl"),
		[]byte(`{"type":"user","message":"test"}`+"\n"),
		0644))

	repoPath := filepath.Join(tmpDir, ResticRepoSubdir)
	passwordFile := filepath.Join(tmpDir, ResticPasswordSubdir)
	statusFile := filepath.Join(tmpDir, ResticStatusSubdir)

	require.NoError(t, generatePassword(passwordFile))

	rc := newTestRC(t)
	require.NoError(t, initRepo(rc, repoPath, passwordFile))

	logger := newSilentLogger()
	paths := []string{claudeDir}

	result, err := runResticBackup(rc.Ctx, logger, repoPath, passwordFile, paths)
	require.NoError(t, err)

	// Update status
	updateStatus(logger, statusFile, result, []string{"claude-code"})

	// Verify status file
	data, err := os.ReadFile(statusFile)
	require.NoError(t, err)

	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))

	assert.NotEmpty(t, status.LastSuccess)
	assert.NotEmpty(t, status.LastSnapshotID)
	assert.Equal(t, 1, status.SuccessCount)
	assert.Contains(t, status.ToolsFound, "claude-code")
}

func TestIntegration_Backup_Idempotent(t *testing.T) {
	requireRestic(t)

	tmpDir := t.TempDir()

	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(claudeDir, "session.jsonl"),
		[]byte(`{"test": true}`+"\n"),
		0644))

	repoPath := filepath.Join(tmpDir, ResticRepoSubdir)
	passwordFile := filepath.Join(tmpDir, ResticPasswordSubdir)

	require.NoError(t, generatePassword(passwordFile))

	rc := newTestRC(t)
	require.NoError(t, initRepo(rc, repoPath, passwordFile))

	logger := newSilentLogger()
	paths := []string{claudeDir}

	// First backup
	result1, err := runResticBackup(rc.Ctx, logger, repoPath, passwordFile, paths)
	require.NoError(t, err)
	assert.Greater(t, result1.FilesNew, 0)

	// Second backup (no changes) - should succeed with 0 new files
	result2, err := runResticBackup(rc.Ctx, logger, repoPath, passwordFile, paths)
	require.NoError(t, err)
	assert.Equal(t, 0, result2.FilesNew,
		"second backup should have 0 new files (nothing changed)")
	assert.Greater(t, result2.FilesUnmodified, 0,
		"second backup should have unmodified files")
}

func TestIntegration_Prune_Works(t *testing.T) {
	requireRestic(t)

	tmpDir := t.TempDir()

	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(claudeDir, "session.jsonl"),
		[]byte(`{"test": true}`+"\n"),
		0644))

	repoPath := filepath.Join(tmpDir, ResticRepoSubdir)
	passwordFile := filepath.Join(tmpDir, ResticPasswordSubdir)

	require.NoError(t, generatePassword(passwordFile))

	rc := newTestRC(t)
	require.NoError(t, initRepo(rc, repoPath, passwordFile))

	logger := newSilentLogger()

	// Create a snapshot first
	_, err := runResticBackup(rc.Ctx, logger, repoPath, passwordFile, []string{claudeDir})
	require.NoError(t, err)

	// Prune should succeed (even with nothing to prune)
	args := []string{
		"-r", repoPath,
		"--password-file", passwordFile,
		"forget",
		"--tag", BackupTag,
		"--keep-within", "48h",
		"--keep-hourly", "24",
		"--keep-daily", "7",
		"--keep-weekly", "4",
		"--keep-monthly", "12",
		"--prune",
	}

	cmd := exec.CommandContext(rc.Ctx, "restic", args...)
	output, err := cmd.CombinedOutput()
	assert.NoError(t, err, "prune should succeed. Output: %s", string(output))
}

func TestIntegration_ListSnapshots_Works(t *testing.T) {
	requireRestic(t)

	tmpDir := t.TempDir()
	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(claudeDir, "session.jsonl"),
		[]byte(`{"test": true}`+"\n"),
		0644))

	repoPath := filepath.Join(tmpDir, ResticRepoSubdir)
	passwordFile := filepath.Join(tmpDir, ResticPasswordSubdir)
	require.NoError(t, generatePassword(passwordFile))

	rc := newTestRC(t)
	require.NoError(t, initRepo(rc, repoPath, passwordFile))

	_, err := runResticBackup(rc.Ctx, newSilentLogger(), repoPath, passwordFile, []string{claudeDir})
	require.NoError(t, err)

	output, err := ListSnapshots(rc, BackupConfig{HomeDir: tmpDir})
	require.NoError(t, err)
	assert.Contains(t, output, "ID")
}
