//go:build integration

package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestIntegrationPullWithStashTracking_SkipsWhenLocalBranchIsAhead(t *testing.T) {
	rc := testutil.TestContext(t)
	cr := setupCloneableRepo(t)

	require.NoError(t, os.WriteFile(filepath.Join(cr.LocalRepo, "app.txt"), []byte("local-ahead\n"), 0o644))
	runGitTestCmd(t, cr.LocalRepo, "add", "app.txt")
	runGitTestCmd(t, cr.LocalRepo, "commit", "-m", "local ahead")

	untracked := filepath.Join(cr.LocalRepo, "notes.txt")
	require.NoError(t, os.WriteFile(untracked, []byte("keep me\n"), 0o644))

	changed, stashRef, err := PullWithStashTracking(rc, cr.LocalRepo, "main")
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, stashRef)
	require.FileExists(t, untracked, "local-ahead branch should not stash local files")
}

func TestIntegrationPullWithStashTracking_RefusesDivergedBranch(t *testing.T) {
	rc := testutil.TestContext(t)
	cr := setupCloneableRepo(t)

	cr.pushNewVersion(t, "v2")

	require.NoError(t, os.WriteFile(filepath.Join(cr.LocalRepo, "app.txt"), []byte("local-diverged\n"), 0o644))
	runGitTestCmd(t, cr.LocalRepo, "add", "app.txt")
	runGitTestCmd(t, cr.LocalRepo, "commit", "-m", "local diverged")

	untracked := filepath.Join(cr.LocalRepo, "notes.txt")
	require.NoError(t, os.WriteFile(untracked, []byte("keep me\n"), 0o644))

	changed, stashRef, err := PullWithStashTracking(rc, cr.LocalRepo, "main")
	require.Error(t, err)
	require.False(t, changed)
	require.Empty(t, stashRef)
	require.Contains(t, err.Error(), "has diverged from origin/main")
	require.FileExists(t, untracked, "diverged branch refusal should happen before stashing")
}
