package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/constants"
	"github.com/stretchr/testify/require"
)

// CloneableRepo holds references to a bare remote, seed repo, and local clone
// for testing git pull operations against a real local git setup.
type CloneableRepo struct {
	RemoteBare string // bare repo used as origin
	SeedRepo   string // repo used to push commits to origin
	LocalRepo  string // clone of origin for pull testing
}

// setupCloneableRepo creates a bare remote, seeds it with one commit, and
// clones it into a local repo. The remote is automatically added to
// constants.TrustedRemotes for the duration of the test.
func setupCloneableRepo(t *testing.T) *CloneableRepo {
	t.Helper()
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

	// Trust the bare repo remote for the duration of the test
	originalTrusted := append([]string(nil), constants.TrustedRemotes...)
	constants.TrustedRemotes = append(constants.TrustedRemotes, remoteBare)
	t.Cleanup(func() { constants.TrustedRemotes = originalTrusted })

	return &CloneableRepo{
		RemoteBare: remoteBare,
		SeedRepo:   seedRepo,
		LocalRepo:  localRepo,
	}
}

// pushNewVersion creates a new commit in the seed repo and pushes it to origin.
func (cr *CloneableRepo) pushNewVersion(t *testing.T, version string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(cr.SeedRepo, "app.txt"), []byte(version+"\n"), 0o644))
	runGitTestCmd(t, cr.SeedRepo, "add", "app.txt")
	runGitTestCmd(t, cr.SeedRepo, "commit", "-m", "seed "+version)
	runGitTestCmd(t, cr.SeedRepo, "push", "origin", "main")
}
