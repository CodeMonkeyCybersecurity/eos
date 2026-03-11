package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func runGitTestCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v failed: %s", args, strings.TrimSpace(string(out)))
	return strings.TrimSpace(string(out))
}

func setupGitRepo(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()
	runGitTestCmd(t, repoDir, "init")
	runGitTestCmd(t, repoDir, "config", "user.email", "eos-tests@example.com")
	runGitTestCmd(t, repoDir, "config", "user.name", "Eos Tests")

	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "tracked.txt"), []byte("base\n"), 0o644))
	runGitTestCmd(t, repoDir, "add", "tracked.txt")
	runGitTestCmd(t, repoDir, "commit", "-m", "initial")
	return repoDir
}

func TestCreateRollbackStash_NoChanges(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	stashRef, err := createRollbackStash(rc, repoDir)
	require.NoError(t, err)
	require.Empty(t, stashRef)
}

func TestCreateRollbackStash_UntrackedChanges(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	untrackedPath := filepath.Join(repoDir, "local-notes.txt")
	require.NoError(t, os.WriteFile(untrackedPath, []byte("keep me\n"), 0o644))

	stashRef, err := createRollbackStash(rc, repoDir)
	require.NoError(t, err)
	require.NotEmpty(t, stashRef)

	status := runGitTestCmd(t, repoDir, "status", "--porcelain")
	require.Empty(t, status, "working tree should be clean after stash")
	require.NoFileExists(t, untrackedPath, "untracked file should be stashed away")

	runGitTestCmd(t, repoDir, "stash", "apply", stashRef)
	require.FileExists(t, untrackedPath, "untracked file should be restored after stash apply")
}

func TestShortRef(t *testing.T) {
	require.Equal(t, "1234", shortRef("1234"))
	require.Equal(t, "12345678...", shortRef("1234567890abcdef"))
	require.Equal(t, "", shortRef(""))
}

func TestRestoreStash_EmptyRef(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	require.NoError(t, RestoreStash(rc, repoDir, ""))
}

func TestNormalizeRepositoryOwnershipForSudoUser_NoSudoContext(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")

	require.NoError(t, normalizeRepositoryOwnershipForSudoUser(rc, repoDir))
}

func TestPullWithStashTracking_NoRemoteChangeRestoresStashImmediately(t *testing.T) {
	rc := testutil.TestContext(t)
	cr := setupCloneableRepo(t)

	untracked := filepath.Join(cr.LocalRepo, "local-only.txt")
	require.NoError(t, os.WriteFile(untracked, []byte("local\n"), 0o644))

	changed, stashRef, err := PullWithStashTracking(rc, cr.LocalRepo, "main")
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, stashRef, "stash ref should clear when no code changed")
	require.FileExists(t, untracked, "untracked file should be restored when pull is no-op")
}
