//go:build integration

package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/constants"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestIntegrationPullWithStashTracking_PreservesUntrackedChanges(t *testing.T) {
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
	t.Cleanup(func() {
		constants.TrustedRemotes = originalTrusted
	})

	changed, stashRef, err := PullWithStashTracking(rc, localRepo, "main")
	require.NoError(t, err)
	require.True(t, changed)
	require.NotEmpty(t, stashRef)
	require.NoFileExists(t, untracked, "untracked file should be stashed during pull")

	err = RestoreStash(rc, localRepo, stashRef)
	require.NoError(t, err)
	require.FileExists(t, untracked, "stashed untracked file should be restorable")
}
