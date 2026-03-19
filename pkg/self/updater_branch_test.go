package self

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/require"
)

func TestCheckGitRepositoryState_FailsForConfiguredBranchMismatch(t *testing.T) {
	repoDir := initUpdaterBranchTestRepo(t, "feature/self-update")

	updater := NewEnhancedEosUpdater(&eos_io.RuntimeContext{Ctx: context.Background()}, &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  repoDir,
			BinaryPath: filepath.Join(repoDir, "eos"),
			BackupDir:  t.TempDir(),
			GitBranch:  "main",
		},
	})

	err := updater.checkGitRepositoryState()
	require.Error(t, err)
	require.Contains(t, err.Error(), "configured update branch main does not match checked-out branch feature/self-update")
}

func TestCheckGitRepositoryState_FailsForDetachedHead(t *testing.T) {
	repoDir := initUpdaterBranchTestRepo(t, "feature/self-update")
	runGitBranchTestCmd(t, repoDir, "checkout", "HEAD~0")

	updater := NewEnhancedEosUpdater(&eos_io.RuntimeContext{Ctx: context.Background()}, &EnhancedUpdateConfig{
		UpdateConfig: &UpdateConfig{
			SourceDir:  repoDir,
			BinaryPath: filepath.Join(repoDir, "eos"),
			BackupDir:  t.TempDir(),
			GitBranch:  "feature/self-update",
		},
	})

	err := updater.checkGitRepositoryState()
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot self-update from detached HEAD")
}

func initUpdaterBranchTestRepo(t *testing.T, branch string) string {
	t.Helper()

	repoDir := t.TempDir()
	runGitBranchTestCmd(t, repoDir, "init")
	runGitBranchTestCmd(t, repoDir, "config", "user.email", "eos-tests@example.com")
	runGitBranchTestCmd(t, repoDir, "config", "user.name", "Eos Tests")
	runGitBranchTestCmd(t, repoDir, "branch", "-M", "main")

	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "tracked.txt"), []byte("base\n"), 0o644))
	runGitBranchTestCmd(t, repoDir, "add", "tracked.txt")
	runGitBranchTestCmd(t, repoDir, "commit", "-m", "initial")

	if branch != "main" {
		runGitBranchTestCmd(t, repoDir, "checkout", "-b", branch)
	}

	return repoDir
}

func runGitBranchTestCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v failed: %s", args, strings.TrimSpace(string(out)))
	return strings.TrimSpace(string(out))
}
