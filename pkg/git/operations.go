// pkg/git/operations.go
//
// Git repository operations - pure business logic for git interactions
// No orchestration, just focused git operations

package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RepositoryState represents the state of a git repository
type RepositoryState struct {
	IsRepository bool
	HasChanges   bool
	CurrentCommit string
	RemoteURL    string
	Branch       string
}

// VerifyRepository checks if a directory is a valid git repository
func VerifyRepository(rc *eos_io.RuntimeContext, repoDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	gitDir := filepath.Join(repoDir, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		return fmt.Errorf("not a git repository: %s", repoDir)
	}

	// Verify remote URL
	cmd := exec.Command("git", "-C", repoDir, "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get git remote: %w", err)
	}

	remoteURL := strings.TrimSpace(string(output))
	logger.Debug("Repository verified", zap.String("remote", remoteURL))

	return nil
}

// CheckRepositoryState checks the current state of a git repository
func CheckRepositoryState(rc *eos_io.RuntimeContext, repoDir string) (*RepositoryState, error) {
	logger := otelzap.Ctx(rc.Ctx)
	state := &RepositoryState{}

	// Check if it's a repository
	gitDir := filepath.Join(repoDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		state.IsRepository = true
	} else {
		return state, fmt.Errorf("not a git repository: %s", repoDir)
	}

	// Check for uncommitted changes
	statusCmd := exec.Command("git", "-C", repoDir, "status", "--porcelain")
	statusOutput, err := statusCmd.Output()
	if err != nil {
		return state, fmt.Errorf("failed to check git status: %w", err)
	}

	state.HasChanges = len(statusOutput) > 0

	if state.HasChanges {
		logger.Debug("Repository has uncommitted changes")
	} else {
		logger.Debug("Working tree is clean")
	}

	// Get current commit
	commitCmd := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD")
	commitOutput, err := commitCmd.Output()
	if err != nil {
		return state, fmt.Errorf("failed to get current commit: %w", err)
	}
	state.CurrentCommit = strings.TrimSpace(string(commitOutput))

	// Get remote URL
	remoteCmd := exec.Command("git", "-C", repoDir, "remote", "get-url", "origin")
	remoteOutput, err := remoteCmd.Output()
	if err != nil {
		logger.Warn("Could not get remote URL", zap.Error(err))
	} else {
		state.RemoteURL = strings.TrimSpace(string(remoteOutput))
	}

	// Get current branch
	branchCmd := exec.Command("git", "-C", repoDir, "rev-parse", "--abbrev-ref", "HEAD")
	branchOutput, err := branchCmd.Output()
	if err != nil {
		logger.Warn("Could not get current branch", zap.Error(err))
	} else {
		state.Branch = strings.TrimSpace(string(branchOutput))
	}

	return state, nil
}

// GetCurrentCommit returns the current git commit hash
func GetCurrentCommit(rc *eos_io.RuntimeContext, repoDir string) (string, error) {
	commitCmd := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD")
	commitOutput, err := commitCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get current commit: %w", err)
	}

	return strings.TrimSpace(string(commitOutput)), nil
}

// PullLatestCode pulls the latest code from the remote repository
// Uses --autostash to handle uncommitted changes safely
func PullLatestCode(rc *eos_io.RuntimeContext, repoDir, branch string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Pulling latest changes from git repository",
		zap.String("repo", repoDir),
		zap.String("branch", branch))

	// Use --autostash to handle uncommitted changes automatically
	// This is safer than manual stash management
	pullCmd := exec.Command("git", "-C", repoDir, "pull", "--autostash", "origin", branch)
	pullOutput, err := pullCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git pull failed: %w\nOutput: %s",
			err, strings.TrimSpace(string(pullOutput)))
	}

	logger.Debug("Git pull completed",
		zap.String("output", strings.TrimSpace(string(pullOutput))))

	return nil
}

// PullWithVerification pulls code and returns whether anything actually changed
func PullWithVerification(rc *eos_io.RuntimeContext, repoDir, branch string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get commit before pull
	commitBefore, err := GetCurrentCommit(rc, repoDir)
	if err != nil {
		return false, fmt.Errorf("failed to get commit before pull: %w", err)
	}

	// Pull changes
	if err := PullLatestCode(rc, repoDir, branch); err != nil {
		return false, err
	}

	// Get commit after pull
	commitAfter, err := GetCurrentCommit(rc, repoDir)
	if err != nil {
		return false, fmt.Errorf("failed to get commit after pull: %w", err)
	}

	codeChanged := commitBefore != commitAfter

	if !codeChanged {
		logger.Info("Already on latest version",
			zap.String("commit", commitAfter[:8]))
		return false, nil
	}

	logger.Info("Updates pulled",
		zap.String("from", commitBefore[:8]),
		zap.String("to", commitAfter[:8]))

	return true, nil
}

// ResetToCommit performs a git reset --hard to a specific commit
// DANGEROUS: Only use when safe (e.g., during rollback with proper checks)
func ResetToCommit(rc *eos_io.RuntimeContext, repoDir, commitHash string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Warn("Performing git reset --hard",
		zap.String("repo", repoDir),
		zap.String("commit", commitHash[:8]))

	resetCmd := exec.Command("git", "-C", repoDir, "reset", "--hard", commitHash)
	resetOutput, err := resetCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git reset failed: %w\nOutput: %s",
			err, strings.TrimSpace(string(resetOutput)))
	}

	logger.Info("Git repository reset successfully",
		zap.String("commit", commitHash[:8]))

	return nil
}
