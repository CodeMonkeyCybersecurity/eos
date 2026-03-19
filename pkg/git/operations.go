// pkg/git/operations.go
//
// Git repository operations - pure business logic for git interactions
// No orchestration, just focused git operations

package git

import (
	"bytes"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	gitPullRetrySleep = time.Sleep
	// runGitPullAttempt executes a single git pull attempt.
	// FIX: Previously set Stderr AND called CombinedOutput(), which panics with
	// "exec: Stderr already set" (Go's exec package disallows this).
	// Solution: Use a shared buffer for both Stdout and Stderr (same as CombinedOutput
	// but without the internal conflict). When interactive, also tee stdin.
	// Reference: https://pkg.go.dev/os/exec#Cmd.CombinedOutput
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		args := []string{"-C", repoDir, "pull", "--ff-only"}
		if autostash {
			args = append(args, "--autostash")
		}
		args = append(args, "origin", branch)
		// #nosec G204 -- args are assembled from fixed tokens plus validated branch/repo inputs.
		pullCmd := exec.Command("git", args...)
		if len(extraEnv) > 0 {
			pullCmd.Env = append(os.Environ(), extraEnv...)
		}

		// Capture combined stdout+stderr into a single buffer.
		// This is what CombinedOutput() does internally, but we do it manually
		// so we can also set Stdin for interactive sessions without conflict.
		var buf bytes.Buffer
		pullCmd.Stdout = &buf
		pullCmd.Stderr = &buf
		if interactive {
			pullCmd.Stdin = os.Stdin
		}
		err := pullCmd.Run()
		return buf.Bytes(), err
	}
)

const (
	gitPullFailureReasonPermanent = "permanent"
	gitPullFailureReasonUnknown   = "unknown"
)

// RepositoryState represents the state of a git repository
type RepositoryState struct {
	IsRepository  bool
	HasChanges    bool
	CurrentCommit string
	RemoteURL     string
	Branch        string
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
	commitOutput, err := runGitOutput(repoDir, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("failed to get current commit: %w", err)
	}

	return strings.TrimSpace(string(commitOutput)), nil
}

func runGitOutput(repoDir string, args ...string) ([]byte, error) {
	// #nosec G204 -- args are assembled from fixed tokens plus validated inputs
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	return cmd.Output()
}

func runGitCombinedOutput(repoDir string, args ...string) ([]byte, error) {
	// #nosec G204 -- args are assembled from fixed tokens plus validated inputs
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	return cmd.CombinedOutput()
}

func shortRef(ref string) string {
	if ref == "" {
		return ""
	}
	if len(ref) <= 8 {
		return ref
	}
	return ref[:8] + "..."
}

// createRollbackStash creates a stash snapshot suitable for rollback recovery.
// It includes untracked files to prevent false-positive "has changes" states
// where stash creation appears to succeed but no stash ref exists.
func createRollbackStash(rc *eos_io.RuntimeContext, repoDir string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	statusOutput, err := runGitOutput(repoDir, "status", "--porcelain")
	if err != nil {
		return "", fmt.Errorf("failed to check git status: %w", err)
	}
	if len(statusOutput) == 0 {
		logger.Debug("No uncommitted changes, no stash needed")
		return "", nil
	}

	logger.Info("Uncommitted changes detected, creating stash for rollback safety",
		zap.String("event", "self_update.git.stash_create"),
		zap.String("message", "eos self-update auto-stash"),
		zap.Bool("include_untracked", true))

	stashOutput, err := runGitCombinedOutput(repoDir, "stash", "push", "--include-untracked", "-m", "eos self-update auto-stash")
	if err != nil {
		return "", fmt.Errorf("failed to create stash: %w\nOutput: %s",
			err, strings.TrimSpace(string(stashOutput)))
	}

	stashOutputStr := strings.TrimSpace(string(stashOutput))
	logger.Debug("Stash command output", zap.String("output", stashOutputStr))

	if strings.Contains(stashOutputStr, "No local changes to save") {
		// Defensive fallback: treat as no-op instead of hard-failing stash ref resolution.
		logger.Info("Stash reported no local changes; continuing without stash ref")
		return "", nil
	}

	// Read the stash commit directly from refs/stash to avoid reflog-index assumptions.
	stashRefOutput, err := runGitOutput(repoDir, "rev-parse", "--verify", "refs/stash")
	if err != nil {
		return "", fmt.Errorf("failed to get stash ref after creating stash: %w\n"+
			"CRITICAL: Stash may exist but ref could not be retrieved.\n"+
			"Manual recovery:\n"+
			"  git -C %s stash list\n"+
			"  git -C %s stash apply stash@{0}",
			err, repoDir, repoDir)
	}

	stashRef := strings.TrimSpace(string(stashRefOutput))
	logger.Info("Stash created successfully for rollback safety",
		zap.String("event", "self_update.git.stash_created"),
		zap.String("ref", shortRef(stashRef)),
		zap.String("symbolic", "refs/stash"))
	return stashRef, nil
}

func normalizeRepositoryOwnershipForSudoUser(rc *eos_io.RuntimeContext, repoDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if os.Geteuid() != 0 {
		return nil
	}

	sudoUID, sudoGID, err := resolveSudoOwnership()
	if err != nil {
		return err
	}
	if sudoUID == "" || sudoGID == "" {
		return nil
	}

	gitDir := filepath.Join(repoDir, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		return fmt.Errorf("cannot stat git dir for ownership normalization: %w", err)
	}
	needsNormalization, err := repositoryOwnershipNeedsNormalization(gitDir, sudoUID, sudoGID)
	if err != nil {
		return fmt.Errorf("failed to inspect git ownership for normalization: %w", err)
	}
	if !needsNormalization {
		logger.Debug("Git ownership already normalized for sudo user",
			zap.String("event", "self_update.git.ownership_already_normalized"),
			zap.String("git_dir", gitDir),
			zap.String("uid", sudoUID),
			zap.String("gid", sudoGID))
		return nil
	}

	// #nosec G204 -- sudoUID/sudoGID validated as integers above
	output, err := exec.Command("chown", "-R", fmt.Sprintf("%s:%s", sudoUID, sudoGID), gitDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to normalize git ownership to %s:%s: %w\nOutput: %s",
			sudoUID, sudoGID, err, strings.TrimSpace(string(output)))
	}

	logger.Debug("Normalized .git ownership for sudo user",
		zap.String("event", "self_update.git.ownership_normalized"),
		zap.String("git_dir", gitDir),
		zap.String("uid", sudoUID),
		zap.String("gid", sudoGID))
	return nil
}

func resolveSudoOwnership() (string, string, error) {
	sudoUID := strings.TrimSpace(os.Getenv("SUDO_UID"))
	sudoGID := strings.TrimSpace(os.Getenv("SUDO_GID"))
	if sudoUID == "" || sudoGID == "" {
		return "", "", nil
	}

	if _, err := strconv.Atoi(sudoUID); err != nil {
		return "", "", fmt.Errorf("invalid SUDO_UID %q: %w", sudoUID, err)
	}
	if _, err := strconv.Atoi(sudoGID); err != nil {
		return "", "", fmt.Errorf("invalid SUDO_GID %q: %w", sudoGID, err)
	}

	return sudoUID, sudoGID, nil
}

func repositoryOwnershipNeedsNormalization(rootPath, wantUID, wantGID string) (bool, error) {
	return firstOwnershipMismatch(rootPath, wantUID, wantGID)
}

func firstOwnershipMismatch(rootPath, wantUID, wantGID string) (bool, error) {
	var mismatch bool
	stopWalk := fmt.Errorf("ownership_mismatch_detected")

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("missing stat metadata for %s", path)
		}
		if strconv.FormatUint(uint64(stat.Uid), 10) != wantUID || strconv.FormatUint(uint64(stat.Gid), 10) != wantGID {
			mismatch = true
			return stopWalk
		}
		return nil
	})
	if err != nil && err != stopWalk {
		return false, err
	}

	return mismatch, nil
}

const (
	pullRelationUpToDate    = "up_to_date"
	pullRelationLocalAhead  = "local_ahead"
	pullRelationRemoteAhead = "remote_ahead"
	pullRelationDiverged    = "diverged"
)

type pullAssessment struct {
	currentBranch string
	targetBranch  string
	commitBefore  string
	remoteCommit  string
	relation      string
}

func currentBranch(repoDir string) (string, error) {
	branchOutput, err := runGitOutput(repoDir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", fmt.Errorf("failed to resolve current branch: %w", err)
	}
	return strings.TrimSpace(string(branchOutput)), nil
}

func assessPullTarget(rc *eos_io.RuntimeContext, repoDir, requestedBranch string) (*pullAssessment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	current, err := currentBranch(repoDir)
	if err != nil {
		return nil, err
	}
	if current == "" || current == "HEAD" {
		return nil, fmt.Errorf("cannot self-update from detached HEAD in %s\n\n"+
			"Check out a branch and retry:\n"+
			"  git -C %s switch main",
			repoDir, repoDir)
	}

	target := strings.TrimSpace(requestedBranch)
	if target == "" {
		target = current
	}
	if target != current {
		logger.Error("Refusing unsafe cross-branch self-update",
			zap.String("event", "self_update.git.pull.branch_mismatch"),
			zap.String("repo", repoDir),
			zap.String("current_branch", current),
			zap.String("target_branch", target))
		return nil, fmt.Errorf("refusing to pull origin/%s while checked out on %s\n\n"+
			"Self-update only fast-forwards the checked-out branch.\n"+
			"Either:\n"+
			"  1. Check out %s and re-run the update\n"+
			"  2. Re-run self-update from the current branch %s",
			target, current, target, current)
	}

	commitBefore, err := GetCurrentCommit(rc, repoDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit before pull: %w", err)
	}

	remoteCommit, err := fetchRemoteBranch(rc, repoDir, target)
	if err != nil {
		return nil, err
	}

	relation, err := classifyCommitRelation(repoDir, commitBefore, remoteCommit)
	if err != nil {
		return nil, err
	}

	logger.Info("Assessed git pull target",
		zap.String("event", "self_update.git.pull.assessed"),
		zap.String("repo", repoDir),
		zap.String("current_branch", current),
		zap.String("target_branch", target),
		zap.String("local_commit", shortRef(commitBefore)),
		zap.String("remote_commit", shortRef(remoteCommit)),
		zap.String("relation", relation))

	return &pullAssessment{
		currentBranch: current,
		targetBranch:  target,
		commitBefore:  commitBefore,
		remoteCommit:  remoteCommit,
		relation:      relation,
	}, nil
}

func classifyCommitRelation(repoDir, localCommit, remoteCommit string) (string, error) {
	if localCommit == remoteCommit {
		return pullRelationUpToDate, nil
	}

	remoteIsAncestor, err := isAncestorCommit(repoDir, remoteCommit, localCommit)
	if err != nil {
		return "", err
	}
	localIsAncestor, err := isAncestorCommit(repoDir, localCommit, remoteCommit)
	if err != nil {
		return "", err
	}

	switch {
	case localIsAncestor && remoteIsAncestor:
		return pullRelationUpToDate, nil
	case localIsAncestor:
		return pullRelationRemoteAhead, nil
	case remoteIsAncestor:
		return pullRelationLocalAhead, nil
	default:
		return pullRelationDiverged, nil
	}
}

func isAncestorCommit(repoDir, maybeAncestor, commit string) (bool, error) {
	// #nosec G204 -- args are assembled from validated commit refs.
	cmd := exec.Command("git", "-C", repoDir, "merge-base", "--is-ancestor", maybeAncestor, commit)
	err := cmd.Run()
	if err == nil {
		return true, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}

	return false, fmt.Errorf("failed to compare commits %s and %s: %w", shortRef(maybeAncestor), shortRef(commit), err)
}

// PullOptions controls pull behavior for self-update and other git consumers.
type PullOptions struct {
	VerifyRemote                  bool
	FailOnMissingHTTPSCredentials bool
	TrackRollbackStash            bool
	VerifyCommitSignatures        bool
	NormalizeOwnershipForSudo     bool
	RecoverMergeConflicts         bool
	FetchFirst                    bool
	Autostash                     bool
}

// PullResult captures the state transition of a pull operation.
type PullResult struct {
	CodeChanged   bool
	StashRef      string
	CommitBefore  string
	CommitAfter   string
	RemoteCommit  string
	PullOutput    string
	CurrentBranch string
	TargetBranch  string
	Relation      string
}

// PullRepository is the single pull engine used by self-update and tests.
func PullRepository(rc *eos_io.RuntimeContext, repoDir, branch string, options PullOptions) (*PullResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	result := &PullResult{}

	logger.Info("Pulling latest changes from git repository",
		zap.String("event", "self_update.git.pull.start"),
		zap.String("repo", repoDir),
		zap.String("branch", branch),
		zap.Bool("track_stash", options.TrackRollbackStash),
		zap.Bool("verify_signatures", options.VerifyCommitSignatures),
		zap.Bool("fetch_first", options.FetchFirst))

	if options.NormalizeOwnershipForSudo {
		if ownErr := normalizeRepositoryOwnershipForSudoUser(rc, repoDir); ownErr != nil {
			logger.Warn("Could not normalize git ownership before update",
				zap.Error(ownErr),
				zap.String("repo", repoDir))
		}
		defer func() {
			if ownErr := normalizeRepositoryOwnershipForSudoUser(rc, repoDir); ownErr != nil {
				logger.Warn("Could not normalize git ownership after update",
					zap.Error(ownErr),
					zap.String("repo", repoDir))
			}
		}()
	}

	if options.RecoverMergeConflicts {
		hasConflicts, conflictedFiles, err := HasMergeConflicts(rc, repoDir)
		if err != nil {
			return nil, fmt.Errorf("failed to check for merge conflicts: %w", err)
		}

		if hasConflicts {
			logger.Warn("Repository has existing merge conflicts, attempting auto-recovery",
				zap.Strings("files", conflictedFiles))

			if err := RecoverFromMergeConflicts(rc, repoDir); err != nil {
				return nil, fmt.Errorf("repository has unresolved merge conflicts: %w\n\n"+
					"Conflicted files: %v\n\n"+
					"Manual recovery required:\n"+
					"  cd %s\n"+
					"  git status                    # See conflict details\n"+
					"  git merge --abort             # Abort the merge\n"+
					"  # OR: git reset --hard HEAD   # Discard all changes\n"+
					"  # Then re-run the update",
					err, conflictedFiles, repoDir)
			}

			logger.Info("Successfully recovered from merge conflicts, proceeding with update")
		}
	}

	if options.VerifyRemote {
		if err := VerifyTrustedRemote(rc, repoDir); err != nil {
			return nil, err
		}
	}

	if options.FailOnMissingHTTPSCredentials {
		if err := EnsureCredentials(rc, repoDir); err != nil {
			return nil, err
		}
	}

	assessment, err := assessPullTarget(rc, repoDir, branch)
	if err != nil {
		return nil, err
	}
	result.CommitBefore = assessment.commitBefore
	result.CommitAfter = assessment.commitBefore
	result.RemoteCommit = assessment.remoteCommit
	result.CurrentBranch = assessment.currentBranch
	result.TargetBranch = assessment.targetBranch
	result.Relation = assessment.relation

	switch assessment.relation {
	case pullRelationUpToDate:
		logger.Info("Already on latest version",
			zap.String("event", "self_update.git.pull.up_to_date_after_fetch"),
			zap.String("branch", assessment.targetBranch),
			zap.String("commit", shortRef(assessment.commitBefore)))
		return result, nil
	case pullRelationLocalAhead:
		logger.Info("Skipping self-update because local branch is already ahead of origin",
			zap.String("event", "self_update.git.pull.local_ahead"),
			zap.String("branch", assessment.targetBranch),
			zap.String("local_commit", shortRef(assessment.commitBefore)),
			zap.String("remote_commit", shortRef(assessment.remoteCommit)))
		return result, nil
	case pullRelationDiverged:
		logger.Error("Refusing self-update because local and remote branches have diverged",
			zap.String("event", "self_update.git.pull.diverged"),
			zap.String("branch", assessment.targetBranch),
			zap.String("local_commit", shortRef(assessment.commitBefore)),
			zap.String("remote_commit", shortRef(assessment.remoteCommit)))
		return nil, fmt.Errorf("local branch %s has diverged from origin/%s\n\n"+
			"Local commit:  %s\n"+
			"Remote commit: %s\n\n"+
			"Self-update only performs fast-forward updates.\n"+
			"Resolve the branch divergence first, then re-run:\n"+
			"  git -C %s status\n"+
			"  git -C %s log --oneline --decorate --graph --max-count=12 --all",
			assessment.targetBranch,
			assessment.targetBranch,
			shortRef(assessment.commitBefore),
			shortRef(assessment.remoteCommit),
			repoDir,
			repoDir)
	}

	if options.TrackRollbackStash {
		result.StashRef, err = createRollbackStash(rc, repoDir)
		if err != nil {
			return nil, err
		}
	}

	autostash := options.Autostash && !options.TrackRollbackStash
	pullOutput, err := runGitPullWithRetry(rc, repoDir, assessment.targetBranch, autostash)
	result.PullOutput = strings.TrimSpace(string(pullOutput))
	if err != nil {
		if result.StashRef != "" {
			logger.Warn("Pull failed, attempting to restore stash",
				zap.String("stash_ref", shortRef(result.StashRef)))

			if restoreErr := RestoreStash(rc, repoDir, result.StashRef); restoreErr != nil {
				logger.Error("Failed to restore stash after failed pull",
					zap.Error(restoreErr),
					zap.String("stash_ref", result.StashRef))
				return nil, fmt.Errorf("pull failed AND stash restore failed\n"+
					"Pull error: %w\n"+
					"Pull output: %s\n\n"+
					"Stash restore error: %v",
					err, result.PullOutput, restoreErr)
			}

			logger.Info("Stash restored successfully after failed pull")
		}

		return nil, fmt.Errorf("git pull failed: %w\nOutput: %s", err, result.PullOutput)
	}

	logger.Debug("Git pull completed", zap.String("output", result.PullOutput))

	commitAfter, err := GetCurrentCommit(rc, repoDir)
	if err != nil {
		if result.StashRef != "" {
			logger.Warn("Failed to get commit after pull, restoring stash")
			if restoreErr := RestoreStash(rc, repoDir, result.StashRef); restoreErr != nil {
				logger.Warn("Best-effort stash restore failed after commit lookup error",
					zap.Error(restoreErr),
					zap.String("stash_ref", shortRef(result.StashRef)))
			}
		}
		return nil, fmt.Errorf("failed to get commit after pull: %w", err)
	}
	result.CommitAfter = commitAfter
	result.CodeChanged = assessment.commitBefore != commitAfter

	if !result.CodeChanged {
		logger.Info("Already on latest version",
			zap.String("commit", shortRef(commitAfter)))

		if result.StashRef != "" {
			logger.Info("No code changes, restoring stash immediately")
			if err := RestoreStash(rc, repoDir, result.StashRef); err != nil {
				return nil, fmt.Errorf("no code changes but stash restore failed: %v", err)
			}
			logger.Info("Stash restored successfully (no code changes)")
			result.StashRef = ""
		}

		return result, nil
	}

	logger.Info("Updates pulled",
		zap.String("event", "self_update.git.pull.updated"),
		zap.String("branch", assessment.targetBranch),
		zap.String("from", shortRef(assessment.commitBefore)),
		zap.String("to", shortRef(commitAfter)))

	if options.VerifyCommitSignatures {
		results, err := VerifyCommitChain(rc, repoDir, assessment.commitBefore, commitAfter)
		if err != nil {
			logger.Error("Commit signature verification failed", zap.Error(err))
		}
		logVerificationWarnings(logger, results)
	}

	if result.StashRef != "" {
		logger.Info("Stash tracked for potential rollback",
			zap.String("ref", shortRef(result.StashRef)))
	}

	return result, nil
}

// PullLatestCode preserves the legacy API while delegating to PullRepository.
func PullLatestCode(rc *eos_io.RuntimeContext, repoDir, branch string) error {
	_, err := PullRepository(rc, repoDir, branch, PullOptions{
		VerifyRemote:                  true,
		FailOnMissingHTTPSCredentials: true,
		Autostash:                     true,
	})
	return err
}

// PullWithVerification preserves the legacy API while delegating to PullRepository.
func PullWithVerification(rc *eos_io.RuntimeContext, repoDir, branch string) (bool, error) {
	result, err := PullRepository(rc, repoDir, branch, PullOptions{
		VerifyRemote:                  true,
		FailOnMissingHTTPSCredentials: true,
		VerifyCommitSignatures:        true,
		Autostash:                     true,
	})
	if err != nil {
		return false, err
	}
	return result.CodeChanged, nil
}

// PullWithStashTracking preserves the legacy API while delegating to PullRepository.
func PullWithStashTracking(rc *eos_io.RuntimeContext, repoDir, branch string) (bool, string, error) {
	result, err := PullRepository(rc, repoDir, branch, PullOptions{
		VerifyRemote:                  true,
		FailOnMissingHTTPSCredentials: true,
		TrackRollbackStash:            true,
		VerifyCommitSignatures:        true,
		NormalizeOwnershipForSudo:     true,
		RecoverMergeConflicts:         true,
		FetchFirst:                    true,
	})
	if err != nil {
		return false, "", err
	}
	return result.CodeChanged, result.StashRef, nil
}

func fetchRemoteBranch(rc *eos_io.RuntimeContext, repoDir, branch string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	args := []string{"-C", repoDir, "fetch", "--prune", "origin", branch}
	// #nosec G204 -- args are assembled from fixed tokens plus validated branch/repo inputs.
	cmd := exec.Command("git", args...)
	if extraEnv := GitPullEnv(); len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	if IsInteractive() {
		cmd.Stdin = os.Stdin
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git fetch failed: %w\nOutput: %s", err, strings.TrimSpace(string(output)))
	}

	remoteCommitOutput, err := runGitOutput(repoDir, "rev-parse", "FETCH_HEAD")
	if err != nil {
		return "", fmt.Errorf("failed to resolve fetched commit: %w", err)
	}

	remoteCommit := strings.TrimSpace(string(remoteCommitOutput))
	logger.Info("Fetched remote branch for pre-pull assessment",
		zap.String("event", "self_update.git.fetch"),
		zap.String("branch", branch),
		zap.String("remote_commit", shortRef(remoteCommit)))

	return remoteCommit, nil
}

func logVerificationWarnings(logger otelzap.LoggerWithCtx, results []*VerificationResult) {
	for _, result := range results {
		for _, warning := range result.Warnings {
			logger.Warn("SECURITY WARNING", zap.String("warning", warning))
		}
	}
}

func runGitPullWithRetry(rc *eos_io.RuntimeContext, repoDir, branch string, autostash bool) ([]byte, error) {
	logger := otelzap.Ctx(rc.Ctx)
	interactive := IsInteractive()
	extraEnv := GitPullEnv()

	var (
		lastOutput []byte
		lastErr    error
		attempts   []string // Collect per-attempt context for diagnostics
	)

	for attempt := 1; attempt <= GitPullMaxAttempts; attempt++ {
		output, err := runGitPullAttempt(repoDir, branch, autostash, interactive, extraEnv)
		if err == nil {
			if attempt > 1 {
				logger.Info("Git pull succeeded after transient failure(s)",
					zap.Int("successful_attempt", attempt),
					zap.Strings("prior_failures", attempts))
			}
			return output, nil
		}

		outputStr := strings.TrimSpace(string(output))
		lastOutput = output
		lastErr = err

		transient, reason := isTransientGitPullFailure(outputStr)
		attempts = append(attempts, fmt.Sprintf("attempt=%d reason=%s", attempt, reason))

		if !transient {
			logger.Warn("Permanent git pull failure, not retrying",
				zap.String("reason", reason),
				zap.String("output", outputStr))
			break
		}

		if attempt == GitPullMaxAttempts {
			logger.Error("Git pull failed after all retry attempts",
				zap.Int("attempts", attempt),
				zap.Strings("failure_history", attempts))
			break
		}

		backoff := retryBackoff(attempt)
		logger.Warn("Transient git pull failure, retrying",
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", GitPullMaxAttempts),
			zap.Duration("backoff", backoff),
			zap.String("reason", reason),
			zap.String("output", outputStr))
		gitPullRetrySleep(backoff)
	}

	return lastOutput, fmt.Errorf("git pull failed after %d attempt(s) [%s]: %w",
		len(attempts), strings.Join(attempts, "; "), lastErr)
}

// retryBackoff calculates backoff duration with jitter to prevent thundering herd.
// Formula: (attempt * base) + random(0, maxJitter).
func retryBackoff(attempt int) time.Duration {
	base := time.Duration(attempt) * GitPullBaseBackoff
	jitter := randomJitterDuration(GitPullMaxJitter)
	return base + jitter
}

func randomJitterDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(max.Nanoseconds()+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// permanentMarkers lists error substrings that indicate non-retryable failures.
// These represent deterministic errors that won't resolve on retry.
// Reference: CLAUDE.md Retry Logic section.
var permanentMarkers = []string{
	"authentication failed",
	"permission denied",
	"repository not found",
	"could not read username",
	"not in trusted whitelist",
	"security violation",
	"invalid credentials",
}

// transientMarkers maps error substrings to reason codes for retryable failures.
// Sources:
//   - HTTP 5xx/429: RFC 9110 sections 15.6.3-15.6.5
//   - Git network errors: git source, observed in production logs
//   - DNS/TLS: OS-level transient failures
var transientMarkers = map[string]string{
	// HTTP gateway/server errors (RFC 9110)
	"requested url returned error: 500": "http_500",
	"requested url returned error: 502": "http_502",
	"requested url returned error: 503": "http_503",
	"requested url returned error: 504": "http_504",
	"requested url returned error: 429": "http_429",
	// TLS errors
	"tls handshake timeout": "tls_timeout",
	// Network-level errors
	"i/o timeout":              "io_timeout",
	"connection reset by peer": "connection_reset",
	"connection refused":       "connection_refused",
	"broken pipe":              "broken_pipe",
	"unexpected eof":           "unexpected_eof",
	// DNS errors
	"temporary failure in name resolution": "dns_temporary_failure",
	"could not resolve host":               "dns_resolution_failure",
	// Git-specific transient errors
	"remote end hung up unexpectedly": "remote_hung_up",
}

func isTransientGitPullFailure(output string) (bool, string) {
	lower := strings.ToLower(strings.TrimSpace(output))

	for _, marker := range permanentMarkers {
		if strings.Contains(lower, marker) {
			return false, gitPullFailureReasonPermanent
		}
	}

	for marker, reason := range transientMarkers {
		if strings.Contains(lower, marker) {
			return true, reason
		}
	}

	return false, gitPullFailureReasonUnknown
}

// RestoreStash restores a specific stash by its SHA ref.
// P0-2 FIX: Used during rollback to restore uncommitted changes.
//
// Handles the common failure mode where `git stash apply` fails with
// "could not restore untracked files from stash" because untracked files
// already exist in the working tree. In this case, we remove the blocking
// untracked files (they came from the stash, so they'll be restored) and retry.
//
// We use 'apply' instead of 'pop' because:
//  1. If apply fails, stash is still preserved for manual recovery
//  2. We can verify apply succeeded before dropping the stash
func RestoreStash(rc *eos_io.RuntimeContext, repoDir, stashRef string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if stashRef == "" {
		logger.Debug("No stash to restore (stashRef empty)")
		return nil
	}

	logger.Info("Restoring stash from rollback",
		zap.String("ref", shortRef(stashRef)))

	applyOutput, err := runGitCombinedOutput(repoDir, "stash", "apply", stashRef)
	if err == nil {
		logger.Info("Stash restored successfully",
			zap.String("ref", shortRef(stashRef)))
		return nil
	}

	outputStr := strings.TrimSpace(string(applyOutput))

	hasConflicts, conflictedFiles, conflictErr := HasMergeConflicts(rc, repoDir)
	if conflictErr == nil && hasConflicts {
		logger.Error("Stash restore produced merge conflicts",
			zap.String("event", "self_update.git.stash_restore_conflict"),
			zap.String("ref", shortRef(stashRef)),
			zap.Strings("files", conflictedFiles))
		return fmt.Errorf("stash restore produced merge conflicts in %v\n"+
			"Output: %s\n\n"+
			"Manual recovery:\n"+
			"  git -C %s status\n"+
			"  git -C %s reset --hard HEAD   # clears the partial apply\n"+
			"  git -C %s stash apply %s      # re-apply once ready",
			conflictedFiles, outputStr, repoDir, repoDir, repoDir, stashRef)
	}

	// Handle "could not restore untracked files from stash":
	// This happens when untracked files that were in the stash already exist
	// in the working tree (e.g., created by a build step between stash and restore).
	// Fix: remove the blocking files then retry apply.
	if !strings.Contains(outputStr, "could not restore untracked files from stash") &&
		!strings.Contains(outputStr, "already exists, no checkout") {
		return fmt.Errorf("failed to restore stash: %w\n"+
			"Output: %s\n\n"+
			"Manual recovery:\n"+
			"  git -C %s stash apply %s",
			err, outputStr, repoDir, stashRef)
	}

	logger.Warn("Stash apply failed due to existing untracked files, removing blockers and retrying",
		zap.String("ref", shortRef(stashRef)))

	// List untracked files from the stash's third parent (the untracked tree)
	// git rev-parse stashRef^3 gives the tree of untracked files
	untrackedTreeOutput, treeErr := runGitOutput(repoDir, "rev-parse", "--verify", stashRef+"^3")
	if treeErr != nil {
		logger.Debug("Stash has no untracked files tree, cannot auto-recover",
			zap.Error(treeErr))
		return fmt.Errorf("failed to restore stash: %w\n"+
			"Output: %s\n\n"+
			"Manual recovery:\n"+
			"  git -C %s stash apply %s",
			err, outputStr, repoDir, stashRef)
	}

	untrackedTree := strings.TrimSpace(string(untrackedTreeOutput))
	filesOutput, filesErr := runGitCombinedOutput(repoDir, "ls-tree", "-r", "--name-only", untrackedTree)
	if filesErr != nil {
		return fmt.Errorf("failed to list stash untracked files: %w", filesErr)
	}

	// Remove the blocking untracked files so stash apply can recreate them.
	// NOTE: These files exist because they were recreated between stash and restore
	// (e.g., by a build step). The stashed versions will replace them.
	for _, fname := range strings.Split(strings.TrimSpace(string(filesOutput)), "\n") {
		if fname == "" {
			continue
		}
		fullPath := filepath.Join(repoDir, fname)
		if _, statErr := os.Stat(fullPath); statErr == nil {
			logger.Info("Removing blocking untracked file to restore stashed version",
				zap.String("file", fname),
				zap.String("reason", "file recreated between stash and restore"))
		}
		if rmErr := os.Remove(fullPath); rmErr != nil && !os.IsNotExist(rmErr) {
			logger.Warn("Could not remove blocking untracked file",
				zap.String("file", fname),
				zap.Error(rmErr))
		}
	}

	// Retry apply after removing blockers
	retryOutput, retryErr := runGitCombinedOutput(repoDir, "stash", "apply", stashRef)
	if retryErr != nil {
		return fmt.Errorf("failed to restore stash after removing blockers: %w\n"+
			"Output: %s\n\n"+
			"Manual recovery:\n"+
			"  git -C %s stash apply %s",
			retryErr, strings.TrimSpace(string(retryOutput)), repoDir, stashRef)
	}

	logger.Info("Stash restored successfully after removing blocking untracked files",
		zap.String("ref", shortRef(stashRef)))
	return nil
}

// HasMergeConflicts checks if the repository has unresolved merge conflicts
// This detects the "needs merge" state that prevents stash/pull operations
func HasMergeConflicts(rc *eos_io.RuntimeContext, repoDir string) (bool, []string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// git status --porcelain shows merge conflicts as lines starting with "UU", "AA", "DD", etc.
	statusCmd := exec.Command("git", "-C", repoDir, "status", "--porcelain")
	statusOutput, err := statusCmd.Output()
	if err != nil {
		return false, nil, fmt.Errorf("failed to check git status: %w", err)
	}

	var conflictedFiles []string
	lines := strings.Split(string(statusOutput), "\n")
	for _, line := range lines {
		if len(line) < 2 {
			continue
		}
		// Merge conflicts show as: UU, AA, DD, AU, UA, DU, UD
		// First two characters are the status codes
		x, y := line[0], line[1]
		isConflict := x == 'U' || y == 'U' || (x == 'A' && y == 'A') || (x == 'D' && y == 'D')
		if isConflict && len(line) > 3 {
			conflictedFiles = append(conflictedFiles, strings.TrimSpace(line[3:]))
		}
	}

	if len(conflictedFiles) > 0 {
		logger.Warn("Repository has merge conflicts",
			zap.Strings("files", conflictedFiles))
		return true, conflictedFiles, nil
	}

	return false, nil, nil
}

// RecoverFromMergeConflicts attempts to automatically resolve merge conflicts
// by resetting to HEAD (discarding the merge attempt)
// Returns true if recovery was successful
func RecoverFromMergeConflicts(rc *eos_io.RuntimeContext, repoDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	hasConflicts, files, err := HasMergeConflicts(rc, repoDir)
	if err != nil {
		return fmt.Errorf("failed to check for conflicts: %w", err)
	}

	if !hasConflicts {
		logger.Debug("No merge conflicts to recover from")
		return nil
	}

	logger.Warn("Attempting automatic recovery from merge conflicts",
		zap.Strings("conflicted_files", files))

	// Try to abort any in-progress merge
	mergeAbortCmd := exec.Command("git", "-C", repoDir, "merge", "--abort")
	if output, err := mergeAbortCmd.CombinedOutput(); err != nil {
		logger.Debug("git merge --abort failed (may not be in merge state)",
			zap.Error(err),
			zap.String("output", string(output)))
	} else {
		logger.Info("Successfully aborted in-progress merge")
		return nil
	}

	// If merge --abort didn't work, try reset --hard HEAD
	// This discards all uncommitted changes but resolves the conflict state
	logger.Warn("Merge abort failed, attempting git reset --hard HEAD")
	resetCmd := exec.Command("git", "-C", repoDir, "reset", "--hard", "HEAD")
	output, err := resetCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reset repository: %w\nOutput: %s\n\n"+
			"Manual recovery required:\n"+
			"  cd %s\n"+
			"  git status  # See conflicted files\n"+
			"  git merge --abort  # Or: git reset --hard HEAD\n"+
			"  # Then re-run install.sh or eos self update",
			err, strings.TrimSpace(string(output)), repoDir)
	}

	logger.Info("Repository reset to clean state",
		zap.String("output", strings.TrimSpace(string(output))))

	return nil
}

// EnsureCleanState ensures the repository is in a clean state before operations
// If conflicts are detected, attempts automatic recovery
// If uncommitted changes exist (non-conflict), they are preserved
func EnsureCleanState(rc *eos_io.RuntimeContext, repoDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// First check for merge conflicts (blocking issue)
	hasConflicts, files, err := HasMergeConflicts(rc, repoDir)
	if err != nil {
		return err
	}

	if hasConflicts {
		logger.Warn("Repository has merge conflicts, attempting recovery",
			zap.Strings("files", files))

		if err := RecoverFromMergeConflicts(rc, repoDir); err != nil {
			return fmt.Errorf("repository has unresolved merge conflicts that could not be auto-resolved: %w", err)
		}

		logger.Info("Successfully recovered from merge conflicts")
	}

	return nil
}

// ResetToCommit performs a git reset --hard to a specific commit
// DANGEROUS: Only use when safe (e.g., during rollback with proper checks)
func ResetToCommit(rc *eos_io.RuntimeContext, repoDir, commitHash string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Warn("Performing git reset --hard",
		zap.String("repo", repoDir),
		zap.String("commit", shortRef(commitHash)))

	resetCmd := exec.Command("git", "-C", repoDir, "reset", "--hard", commitHash)
	resetOutput, err := resetCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git reset failed: %w\nOutput: %s",
			err, strings.TrimSpace(string(resetOutput)))
	}

	logger.Info("Git repository reset successfully",
		zap.String("commit", shortRef(commitHash)))

	return nil
}
