package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/constants"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestPullRepository_FetchFirstSkipsStashWhenRemoteUnchanged(t *testing.T) {
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

	origRun := runGitPullAttempt
	t.Cleanup(func() { runGitPullAttempt = origRun })
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		t.Fatal("runGitPullAttempt should not run when fetch proves no update is needed")
		return nil, nil
	}

	result, err := PullRepository(rc, localRepo, "main", PullOptions{
		VerifyRemote:                  true,
		FailOnMissingHTTPSCredentials: true,
		TrackRollbackStash:            true,
		FetchFirst:                    true,
	})
	require.NoError(t, err)
	require.False(t, result.CodeChanged)
	require.Empty(t, result.StashRef)
	require.FileExists(t, untracked, "untracked file should remain untouched when remote is unchanged")
}

func TestPullLatestCode_FailsEarlyWithoutHTTPSCredentials(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://gitea.cybermonkey.sh/cybermonkey/eos.git")

	origRun := runGitPullAttempt
	t.Cleanup(func() { runGitPullAttempt = origRun })
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		t.Fatal("git pull should not start when HTTPS credentials are not configured")
		return nil, nil
	}

	err := PullLatestCode(rc, dir, "main")
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential.helper")
}

func TestPullRepository_PullsRemoteChangeAndTracksRollbackStash(t *testing.T) {
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

	require.NoError(t, os.WriteFile(filepath.Join(seedRepo, "app.txt"), []byte("v2\n"), 0o644))
	runGitTestCmd(t, seedRepo, "add", "app.txt")
	runGitTestCmd(t, seedRepo, "commit", "-m", "seed v2")
	runGitTestCmd(t, seedRepo, "push", "origin", "main")

	untracked := filepath.Join(localRepo, "local-dev-notes.txt")
	require.NoError(t, os.WriteFile(untracked, []byte("my local notes\n"), 0o644))

	originalTrusted := append([]string(nil), constants.TrustedRemotes...)
	constants.TrustedRemotes = append(constants.TrustedRemotes, remoteBare)
	t.Cleanup(func() { constants.TrustedRemotes = originalTrusted })

	result, err := PullRepository(rc, localRepo, "main", PullOptions{
		VerifyRemote:                  true,
		FailOnMissingHTTPSCredentials: true,
		TrackRollbackStash:            true,
		VerifyCommitSignatures:        true,
		FetchFirst:                    true,
	})
	require.NoError(t, err)
	require.True(t, result.CodeChanged)
	require.NotEmpty(t, result.StashRef)
	require.NoFileExists(t, untracked, "untracked file should stay stashed until rollback/restore")

	require.NoError(t, RestoreStash(rc, localRepo, result.StashRef))
	require.FileExists(t, untracked)
}

func TestPullRepository_RestoresStashOnPullFailure(t *testing.T) {
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

	untracked := filepath.Join(localRepo, "local-dev-notes.txt")
	require.NoError(t, os.WriteFile(untracked, []byte("my local notes\n"), 0o644))

	originalTrusted := append([]string(nil), constants.TrustedRemotes...)
	constants.TrustedRemotes = append(constants.TrustedRemotes, remoteBare)
	t.Cleanup(func() { constants.TrustedRemotes = originalTrusted })

	origRun := runGitPullAttempt
	t.Cleanup(func() { runGitPullAttempt = origRun })
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		return []byte("remote: Authentication failed"), os.ErrPermission
	}

	_, err := PullRepository(rc, localRepo, "main", PullOptions{
		VerifyRemote:                  true,
		FailOnMissingHTTPSCredentials: true,
		TrackRollbackStash:            true,
	})
	require.Error(t, err)
	require.FileExists(t, untracked, "stash should be restored when pull fails")
}

func TestPullRepository_FailsBeforePullForUntrustedRemote(t *testing.T) {
	rc := newTestRC(t)
	dir := initTestRepo(t, "https://evil.com/malicious/eos.git")

	origRun := runGitPullAttempt
	t.Cleanup(func() { runGitPullAttempt = origRun })
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		t.Fatal("git pull should not run for an untrusted remote")
		return nil, nil
	}

	_, err := PullRepository(rc, dir, "main", PullOptions{
		VerifyRemote:                  true,
		FailOnMissingHTTPSCredentials: true,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "SECURITY VIOLATION")
}
