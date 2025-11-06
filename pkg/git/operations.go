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
// SECURITY: Verifies remote URL is trusted before pulling
func PullLatestCode(rc *eos_io.RuntimeContext, repoDir, branch string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Pulling latest changes from git repository",
		zap.String("repo", repoDir),
		zap.String("branch", branch))

	// SECURITY CHECK: Verify remote is trusted BEFORE pulling
	if err := VerifyTrustedRemote(rc, repoDir); err != nil {
		return err  // Error already includes detailed message
	}

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
// SECURITY: Verifies remote URL before pulling, verifies commit signatures after pulling
func PullWithVerification(rc *eos_io.RuntimeContext, repoDir, branch string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get commit before pull
	commitBefore, err := GetCurrentCommit(rc, repoDir)
	if err != nil {
		return false, fmt.Errorf("failed to get commit before pull: %w", err)
	}

	// Pull changes (includes remote verification)
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

	// SECURITY CHECK: Verify GPG signatures on new commits
	results, err := VerifyCommitChain(rc, repoDir, commitBefore, commitAfter)
	if err != nil {
		logger.Error("Commit signature verification failed", zap.Error(err))
		// Don't fail update for unsigned commits (yet), just warn
		// This will be enforced when GPG signing is standard practice
	}

	// Log warnings from signature verification
	for _, result := range results {
		for _, warning := range result.Warnings {
			logger.Warn("SECURITY WARNING", zap.String("warning", warning))
		}
	}

	return true, nil
}

// PullWithStashTracking pulls code with manual stash management for rollback safety
// P0-2 FIX: Returns stash ref so rollback can verify safe to reset and restore changes
// SECURITY: Verifies remote URL before pulling, verifies commit signatures after pulling
//
// Returns:
//   - codeChanged: true if commits changed, false if already up-to-date
//   - stashRef: full SHA of stash (e.g., "abc123def...") or empty string if no stash created
//   - error: non-nil if operation failed
func PullWithStashTracking(rc *eos_io.RuntimeContext, repoDir, branch string) (codeChanged bool, stashRef string, err error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Pulling latest changes with stash tracking for rollback safety",
		zap.String("repo", repoDir),
		zap.String("branch", branch))

	// SECURITY CHECK: Verify remote is trusted BEFORE pulling
	if err := VerifyTrustedRemote(rc, repoDir); err != nil {
		return false, "", err  // Error already includes detailed message
	}

	// Get commit before pull
	commitBefore, err := GetCurrentCommit(rc, repoDir)
	if err != nil {
		return false, "", fmt.Errorf("failed to get commit before pull: %w", err)
	}

	// Check if we have uncommitted changes
	statusCmd := exec.Command("git", "-C", repoDir, "status", "--porcelain")
	statusOutput, err := statusCmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("failed to check git status: %w", err)
	}

	hasChanges := len(statusOutput) > 0

	// If we have changes, create a stash BEFORE pulling
	if hasChanges {
		logger.Info("Uncommitted changes detected, creating stash for rollback safety",
			zap.String("message", "eos self-update auto-stash"))

		// Create stash with descriptive message
		stashCmd := exec.Command("git", "-C", repoDir, "stash", "push", "-m", "eos self-update auto-stash")
		stashOutput, err := stashCmd.CombinedOutput()
		if err != nil {
			return false, "", fmt.Errorf("failed to create stash: %w\nOutput: %s",
				err, strings.TrimSpace(string(stashOutput)))
		}

		logger.Debug("Stash created", zap.String("output", strings.TrimSpace(string(stashOutput))))

		// Get stash ref (full SHA of stash@{0})
		// CRITICAL: We need the full SHA, not symbolic ref, because stash@{0} changes
		// when new stashes are created. The SHA is immutable.
		stashRefCmd := exec.Command("git", "-C", repoDir, "rev-parse", "stash@{0}")
		stashRefOutput, err := stashRefCmd.Output()
		if err != nil {
			// This is critical - if we can't get stash ref, we can't safely rollback
			return false, "", fmt.Errorf("failed to get stash ref after creating stash: %w\n"+
				"CRITICAL: Stash was created but ref cannot be retrieved.\n"+
				"Manual recovery required:\n"+
				"  git -C %s stash list\n"+
				"  git -C %s stash pop  # If you want to restore changes",
				err, repoDir, repoDir)
		}

		stashRef = strings.TrimSpace(string(stashRefOutput))
		logger.Info("Stash created successfully for rollback safety",
			zap.String("ref", stashRef[:8]+"..."),
			zap.String("symbolic", "stash@{0}"))
	} else {
		logger.Debug("No uncommitted changes, no stash needed")
	}

	// Now pull WITHOUT --autostash (we already manually stashed if needed)
	pullCmd := exec.Command("git", "-C", repoDir, "pull", "origin", branch)
	pullOutput, err := pullCmd.CombinedOutput()
	if err != nil {
		// Pull failed - try to restore stash if we created one
		if stashRef != "" {
			logger.Warn("Pull failed, attempting to restore stash",
				zap.String("stash_ref", stashRef[:8]+"..."))

			// Use 'git stash apply <ref>' instead of 'git stash pop'
			// This is safer because it doesn't remove the stash if apply fails
			applyCmd := exec.Command("git", "-C", repoDir, "stash", "apply", stashRef)
			applyOutput, applyErr := applyCmd.CombinedOutput()
			if applyErr != nil {
				logger.Error("Failed to restore stash after failed pull",
					zap.Error(applyErr),
					zap.String("output", string(applyOutput)),
					zap.String("stash_ref", stashRef))
				return false, "", fmt.Errorf("pull failed AND stash restore failed\n"+
					"Pull error: %w\n"+
					"Pull output: %s\n\n"+
					"Stash restore error: %v\n"+
					"Stash restore output: %s\n\n"+
					"Manual recovery required:\n"+
					"  git -C %s stash apply %s",
					err, strings.TrimSpace(string(pullOutput)),
					applyErr, strings.TrimSpace(string(applyOutput)),
					repoDir, stashRef)
			}

			logger.Info("Stash restored successfully after failed pull")
		}

		return false, "", fmt.Errorf("git pull failed: %w\nOutput: %s",
			err, strings.TrimSpace(string(pullOutput)))
	}

	logger.Debug("Git pull completed",
		zap.String("output", strings.TrimSpace(string(pullOutput))))

	// Get commit after pull
	commitAfter, err := GetCurrentCommit(rc, repoDir)
	if err != nil {
		// Pull succeeded but can't get commit - try to restore stash
		if stashRef != "" {
			logger.Warn("Failed to get commit after pull, restoring stash")
			applyCmd := exec.Command("git", "-C", repoDir, "stash", "apply", stashRef)
			_ = applyCmd.Run() // Best effort
		}
		return false, stashRef, fmt.Errorf("failed to get commit after pull: %w", err)
	}

	codeChanged = commitBefore != commitAfter

	if !codeChanged {
		logger.Info("Already on latest version",
			zap.String("commit", commitAfter[:8]))

		// No code changes - restore stash immediately (don't need rollback capability)
		if stashRef != "" {
			logger.Info("No code changes, restoring stash immediately")
			applyCmd := exec.Command("git", "-C", repoDir, "stash", "apply", stashRef)
			applyOutput, applyErr := applyCmd.CombinedOutput()
			if applyErr != nil {
				logger.Warn("Failed to restore stash after no-op pull",
					zap.Error(applyErr),
					zap.String("output", string(applyOutput)))
				// Don't fail the operation, just warn
				return false, stashRef, fmt.Errorf("no code changes but stash restore failed: %v\n"+
					"Manual recovery: git -C %s stash apply %s",
					applyErr, repoDir, stashRef)
			}
			logger.Info("Stash restored successfully (no code changes)")
			stashRef = "" // Clear stash ref - changes restored, no rollback needed
		}

		return false, stashRef, nil
	}

	logger.Info("Updates pulled",
		zap.String("from", commitBefore[:8]),
		zap.String("to", commitAfter[:8]))

	// SECURITY CHECK: Verify GPG signatures on new commits
	results, err := VerifyCommitChain(rc, repoDir, commitBefore, commitAfter)
	if err != nil {
		logger.Error("Commit signature verification failed", zap.Error(err))
		// Don't fail update for unsigned commits (yet), just warn
		// This will be enforced when GPG signing is standard practice
	}

	// Log warnings from signature verification
	for _, result := range results {
		for _, warning := range result.Warnings {
			logger.Warn("SECURITY WARNING", zap.String("warning", warning))
		}
	}

	// Return with stash ref tracked for rollback
	if stashRef != "" {
		logger.Info("Stash tracked for potential rollback",
			zap.String("ref", stashRef[:8]+"..."))
	}

	return true, stashRef, nil
}

// RestoreStash restores a specific stash by its SHA ref
// P0-2 FIX: Used during rollback to restore uncommitted changes
func RestoreStash(rc *eos_io.RuntimeContext, repoDir, stashRef string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if stashRef == "" {
		logger.Debug("No stash to restore (stashRef empty)")
		return nil
	}

	logger.Info("Restoring stash from rollback",
		zap.String("ref", stashRef[:8]+"..."))

	// Use 'git stash apply <ref>' to restore the stash
	// We use 'apply' instead of 'pop' because:
	// 1. If apply fails, stash is still preserved for manual recovery
	// 2. We can verify apply succeeded before dropping the stash
	applyCmd := exec.Command("git", "-C", repoDir, "stash", "apply", stashRef)
	applyOutput, err := applyCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restore stash: %w\n"+
			"Output: %s\n\n"+
			"Manual recovery:\n"+
			"  git -C %s stash apply %s",
			err, strings.TrimSpace(string(applyOutput)),
			repoDir, stashRef)
	}

	logger.Info("Stash restored successfully",
		zap.String("ref", stashRef[:8]+"..."))

	return nil
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
