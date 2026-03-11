package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/constants"
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
}

func TestRestoreStash_EmptyRef(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	require.NoError(t, RestoreStash(rc, repoDir, ""))
}

func TestNormalizeRepositoryOwnershipForSudoUser_NoSudoContext(t *testing.T) {
	rc := testutil.TestContext(t)
	repoDir := setupGitRepo(t)

	origUID := os.Getenv("SUDO_UID")
	origGID := os.Getenv("SUDO_GID")
	t.Cleanup(func() {
		_ = os.Setenv("SUDO_UID", origUID)
		_ = os.Setenv("SUDO_GID", origGID)
	})
	_ = os.Unsetenv("SUDO_UID")
	_ = os.Unsetenv("SUDO_GID")

	require.NoError(t, normalizeRepositoryOwnershipForSudoUser(rc, repoDir))
}

func TestPullWithStashTracking_NoRemoteChangeRestoresStashImmediately(t *testing.T) {
	rc := testutil.TestContext(t)
	baseDir := t.TempDir()

	remoteBare := filepath.Join(baseDir, "origin.git")
	runGitTestCmd(t, baseDir, "init", "--bare", remoteBare)

	seedRepo := filepath.Join(baseDir, "seed")
	require.NoError(t, os.MkdirAll(seedRepo, 0o755))
	runGitTestCmd(t, seedRepo, "init")
	runGitTestCmd(t, seedRepo, "config", "user.email", "eos-tests@example.com")
	runGitTestCmd(t, seedRepo, "config", "user.name", "Eos Tests")
	runGitTestCmd(t, seedRepo, "branch", "-M", "main")
	require.NoError(t, os.WriteFile(filepath.Join(seedRepo, "app.txt"), []byte("v1\n"), 0o644))
	runGitTestCmd(t, seedRepo, "add", "app.txt")
	runGitTestCmd(t, seedRepo, "commit", "-m", "seed v1")
	runGitTestCmd(t, seedRepo, "remote", "add", "origin", remoteBare)
	runGitTestCmd(t, seedRepo, "push", "-u", "origin", "main")

	localRepo := filepath.Join(baseDir, "local")
	runGitTestCmd(t, baseDir, "clone", "--branch", "main", remoteBare, localRepo)
	runGitTestCmd(t, localRepo, "config", "user.email", "eos-tests@example.com")
	runGitTestCmd(t, localRepo, "config", "user.name", "Eos Tests")

	untracked := filepath.Join(localRepo, "local-only.txt")
	require.NoError(t, os.WriteFile(untracked, []byte("local\n"), 0o644))

	originalTrusted := append([]string(nil), constants.TrustedRemotes...)
	constants.TrustedRemotes = append(constants.TrustedRemotes, remoteBare)
	t.Cleanup(func() { constants.TrustedRemotes = originalTrusted })

	changed, stashRef, err := PullWithStashTracking(rc, localRepo, "main")
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, stashRef, "stash ref should clear when no code changed")
	require.FileExists(t, untracked, "untracked file should be restored when pull is no-op")
}
