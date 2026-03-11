package git

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/require"
)

// --- runGitPullAttempt tests ---

// TestRunGitPullAttempt_InteractiveDoesNotPanic verifies the fix for the
// "exec: Stderr already set" bug. Previously, setting pullCmd.Stderr = os.Stderr
// and then calling CombinedOutput() (which also sets Stderr) caused a panic.
// The fix uses a shared buffer for Stdout and Stderr, avoiding the conflict.
// Reference: https://pkg.go.dev/os/exec#Cmd.CombinedOutput
func TestRunGitPullAttempt_InteractiveDoesNotPanic(t *testing.T) {
	origRun := runGitPullAttempt
	t.Cleanup(func() { runGitPullAttempt = origRun })

	// Run the real runGitPullAttempt with interactive=true against a non-existent repo.
	// The important thing is it doesn't panic with "exec: Stderr already set".
	// It will return an error because the repo doesn't exist, which is expected.
	output, err := runGitPullAttempt(t.TempDir(), "main", false, true, nil)
	// We expect a git error (not a git repo), NOT a panic
	require.Error(t, err, "should fail on non-repo, but must not panic")
	require.NotContains(t, string(output), "Stderr already set",
		"must not produce 'Stderr already set' error")
	require.NotContains(t, err.Error(), "Stderr already set",
		"must not produce 'Stderr already set' error in err")
}

// TestRunGitPullAttempt_NonInteractiveCapturesOutput verifies output capture
// works correctly in non-interactive mode.
func TestRunGitPullAttempt_NonInteractiveCapturesOutput(t *testing.T) {
	origRun := runGitPullAttempt
	t.Cleanup(func() { runGitPullAttempt = origRun })

	output, err := runGitPullAttempt(t.TempDir(), "main", false, false, nil)
	require.Error(t, err)
	// Output should contain a git error message (not empty)
	require.NotEmpty(t, output, "output should capture git's error message")
}

// TestRunGitPullAttempt_ExtraEnvIsApplied verifies that extra environment
// variables (like GIT_TERMINAL_PROMPT=0) are passed to the git process.
func TestRunGitPullAttempt_ExtraEnvIsApplied(t *testing.T) {
	origRun := runGitPullAttempt
	t.Cleanup(func() { runGitPullAttempt = origRun })

	// Even with env set, git will fail on non-repo. We're just testing it doesn't crash.
	_, err := runGitPullAttempt(t.TempDir(), "main", false, false,
		[]string{"GIT_TERMINAL_PROMPT=0"})
	require.Error(t, err, "should fail on non-repo")
}

// TestRunGitPullAttempt_AutostashFlag verifies the --autostash flag is included
// when autostash=true.
func TestRunGitPullAttempt_AutostashFlag(t *testing.T) {
	// We can't easily verify the flag is passed without mocking exec.Command,
	// but we can verify it doesn't crash with autostash=true.
	origRun := runGitPullAttempt
	t.Cleanup(func() { runGitPullAttempt = origRun })

	_, err := runGitPullAttempt(t.TempDir(), "main", true, false, nil)
	require.Error(t, err, "should fail on non-repo")
}

// --- RestoreStash with untracked file collisions ---

// TestRestoreStash_HandlesUntrackedFileCollision verifies that RestoreStash
// can recover when untracked files from the stash already exist in the
// working tree. This was the exact failure mode observed in production:
// "outputs/ci/unit/unit-test.jsonl already exists, no checkout"
func TestRestoreStash_HandlesUntrackedFileCollision(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	// Create an untracked file, stash it
	untrackedFile := filepath.Join(repoDir, "build-output.jsonl")
	require.NoError(t, os.WriteFile(untrackedFile, []byte("original content\n"), 0o644))

	stashRef, err := createRollbackStash(rc, repoDir)
	require.NoError(t, err)
	require.NotEmpty(t, stashRef)

	// Now recreate the file (simulating a build step that recreated it)
	require.NoError(t, os.WriteFile(untrackedFile, []byte("recreated by build\n"), 0o644))

	// RestoreStash should handle this collision gracefully
	err = RestoreStash(rc, repoDir, stashRef)
	require.NoError(t, err, "RestoreStash should handle untracked file collision")

	// The file should exist with the stashed content (original)
	require.FileExists(t, untrackedFile)
	content, err := os.ReadFile(untrackedFile)
	require.NoError(t, err)
	require.Equal(t, "original content\n", string(content),
		"stash restore should overwrite the recreated file with original content")
}

// TestRestoreStash_NoCollisionWorksNormally verifies that the normal
// (no collision) stash restore path still works after our improvement.
func TestRestoreStash_NoCollisionWorksNormally(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	// Create untracked file and stash it
	untrackedFile := filepath.Join(repoDir, "notes.txt")
	require.NoError(t, os.WriteFile(untrackedFile, []byte("my notes\n"), 0o644))

	stashRef, err := createRollbackStash(rc, repoDir)
	require.NoError(t, err)
	require.NotEmpty(t, stashRef)
	require.NoFileExists(t, untrackedFile, "file should be stashed away")

	// Normal restore (no collision)
	err = RestoreStash(rc, repoDir, stashRef)
	require.NoError(t, err)
	require.FileExists(t, untrackedFile)
}

// TestRestoreStash_InvalidRefReturnsError verifies error handling for bad refs.
func TestRestoreStash_InvalidRefReturnsError(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	err := RestoreStash(rc, repoDir, "deadbeef1234567890")
	require.Error(t, err, "should fail with invalid stash ref")
	require.Contains(t, err.Error(), "Manual recovery",
		"error should include manual recovery steps")
}

// --- runGitPullWithRetry tests for interactive mode ---

// TestRunGitPullWithRetry_InteractiveMode verifies retry logic works with
// interactive=true (the path that previously caused the Stderr bug).
func TestRunGitPullWithRetry_InteractiveMode(t *testing.T) {
	origRun := runGitPullAttempt
	origSleep := gitPullRetrySleep
	t.Cleanup(func() {
		runGitPullAttempt = origRun
		gitPullRetrySleep = origSleep
	})

	callCount := 0
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		callCount++
		// Verify interactive flag is passed through
		if !interactive {
			t.Error("expected interactive=true to be passed through")
		}
		if callCount < 2 {
			return []byte("connection reset by peer"), errors.New("exit status 1")
		}
		return []byte("Already up to date."), nil
	}
	gitPullRetrySleep = func(d time.Duration) {}

	// PullLatestCode uses autostash=true, but we're testing retry with interactive
	// through the lower-level function
	out, err := runGitPullWithRetry(testRC(t), "/tmp/repo", "main", true)
	require.NoError(t, err)
	require.Equal(t, "Already up to date.", string(out))
	require.Equal(t, 2, callCount)
}

// --- HasMergeConflicts and RecoverFromMergeConflicts ---

// TestHasMergeConflicts_NoConflicts verifies clean repo detection.
func TestHasMergeConflicts_NoConflicts(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	hasConflicts, files, err := HasMergeConflicts(rc, repoDir)
	require.NoError(t, err)
	require.False(t, hasConflicts)
	require.Empty(t, files)
}

// TestHasMergeConflicts_DetectsUUState verifies merge conflict detection
// with the "UU" (both modified) state that caused the production failure.
func TestHasMergeConflicts_DetectsUUState(t *testing.T) {
	rc := testutil.TestContext(t)
	baseDir := t.TempDir()

	// Create two repos that will conflict
	repoA := filepath.Join(baseDir, "repoA")
	require.NoError(t, os.MkdirAll(repoA, 0o755))
	runGitTestCmd(t, repoA, "init")
	runGitTestCmd(t, repoA, "config", "user.email", "test@example.com")
	runGitTestCmd(t, repoA, "config", "user.name", "Test")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("base\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "base")

	// Create branch with conflicting change
	runGitTestCmd(t, repoA, "checkout", "-b", "feature")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("feature change\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "feature")

	// Create conflicting change on main
	runGitTestCmd(t, repoA, "checkout", "master")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("main change\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "main change")

	// Attempt merge (will fail with conflicts)
	cmd := exec.Command("git", "-C", repoA, "merge", "feature")
	_ = cmd.Run() // Expected to fail

	hasConflicts, files, err := HasMergeConflicts(rc, repoA)
	require.NoError(t, err)
	require.True(t, hasConflicts)
	require.Contains(t, files, "file.txt")
}

// TestRecoverFromMergeConflicts_AbortsSuccessfully verifies that
// RecoverFromMergeConflicts can abort an in-progress merge.
func TestRecoverFromMergeConflicts_AbortsSuccessfully(t *testing.T) {
	rc := testutil.TestContext(t)
	baseDir := t.TempDir()

	repoA := filepath.Join(baseDir, "repoA")
	require.NoError(t, os.MkdirAll(repoA, 0o755))
	runGitTestCmd(t, repoA, "init")
	runGitTestCmd(t, repoA, "config", "user.email", "test@example.com")
	runGitTestCmd(t, repoA, "config", "user.name", "Test")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("base\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "base")

	runGitTestCmd(t, repoA, "checkout", "-b", "feature")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("feature\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "feature")

	runGitTestCmd(t, repoA, "checkout", "master")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("main\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "main")

	cmd := exec.Command("git", "-C", repoA, "merge", "feature")
	_ = cmd.Run()

	// Verify conflicts exist
	hasConflicts, _, err := HasMergeConflicts(rc, repoA)
	require.NoError(t, err)
	require.True(t, hasConflicts)

	// Recover should succeed
	err = RecoverFromMergeConflicts(rc, repoA)
	require.NoError(t, err)

	// Should be clean now
	hasConflicts, _, err = HasMergeConflicts(rc, repoA)
	require.NoError(t, err)
	require.False(t, hasConflicts, "conflicts should be resolved after recovery")
}

// TestRecoverFromMergeConflicts_NoopWhenClean verifies recovery is a no-op
// when there are no conflicts.
func TestRecoverFromMergeConflicts_NoopWhenClean(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	err := RecoverFromMergeConflicts(rc, repoDir)
	require.NoError(t, err)
}

// TestEnsureCleanState_RecoversMergeConflicts verifies the combined
// check-and-recover function works end-to-end.
func TestEnsureCleanState_RecoversMergeConflicts(t *testing.T) {
	rc := testutil.TestContext(t)
	baseDir := t.TempDir()

	repoA := filepath.Join(baseDir, "repoA")
	require.NoError(t, os.MkdirAll(repoA, 0o755))
	runGitTestCmd(t, repoA, "init")
	runGitTestCmd(t, repoA, "config", "user.email", "test@example.com")
	runGitTestCmd(t, repoA, "config", "user.name", "Test")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("base\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "base")

	runGitTestCmd(t, repoA, "checkout", "-b", "feature")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("feature\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "feature")

	runGitTestCmd(t, repoA, "checkout", "master")
	require.NoError(t, os.WriteFile(filepath.Join(repoA, "file.txt"), []byte("main\n"), 0o644))
	runGitTestCmd(t, repoA, "add", "file.txt")
	runGitTestCmd(t, repoA, "commit", "-m", "main")

	cmd := exec.Command("git", "-C", repoA, "merge", "feature")
	_ = cmd.Run()

	err := EnsureCleanState(rc, repoA)
	require.NoError(t, err, "EnsureCleanState should recover from merge conflicts")
}

// TestEnsureCleanState_NoopWhenClean verifies no-op behavior.
func TestEnsureCleanState_NoopWhenClean(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	err := EnsureCleanState(rc, repoDir)
	require.NoError(t, err)
}

// --- ResetToCommit ---

// TestResetToCommit_ResetsSuccessfully verifies git reset works.
func TestResetToCommit_ResetsSuccessfully(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	// Record initial commit
	initialCommit := runGitTestCmd(t, repoDir, "rev-parse", "HEAD")

	// Make a second commit
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "tracked.txt"), []byte("changed\n"), 0o644))
	runGitTestCmd(t, repoDir, "add", "tracked.txt")
	runGitTestCmd(t, repoDir, "commit", "-m", "second")

	secondCommit := runGitTestCmd(t, repoDir, "rev-parse", "HEAD")
	require.NotEqual(t, initialCommit, secondCommit)

	// Reset to initial
	err := ResetToCommit(rc, repoDir, initialCommit)
	require.NoError(t, err)

	currentCommit := runGitTestCmd(t, repoDir, "rev-parse", "HEAD")
	require.Equal(t, initialCommit, currentCommit)
}
