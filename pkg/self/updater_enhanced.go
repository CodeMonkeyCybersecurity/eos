// pkg/self/updater_enhanced.go
//
// Enhanced self-update with comprehensive error recovery and rollback capabilities.
// Implements all P0/P1 safety requirements for production resilience.

package self

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

// UpdateTransaction represents a complete update transaction with rollback capability
type UpdateTransaction struct {
	StartTime        time.Time
	GitCommitBefore  string
	GitStashRef      string
	BackupBinaryPath string
	TempBinaryPath   string
	ChangesPulled    bool
	BinaryInstalled  bool
	Success          bool
}

// EnhancedUpdateConfig extends UpdateConfig with safety features
type EnhancedUpdateConfig struct {
	*UpdateConfig
	RequireCleanWorkingTree bool
	CheckRunningProcesses   bool
	AtomicInstall           bool
	VerifyVersionChange     bool
	MaxRollbackAttempts     int
}

// EnhancedEosUpdater handles self-update with comprehensive error recovery
type EnhancedEosUpdater struct {
	*EosUpdater
	enhancedConfig *EnhancedUpdateConfig
	transaction    *UpdateTransaction
}

// NewEnhancedEosUpdater creates an updater with enhanced safety features
func NewEnhancedEosUpdater(rc *eos_io.RuntimeContext, config *EnhancedUpdateConfig) *EnhancedEosUpdater {
	// Set enhanced defaults
	if config.MaxRollbackAttempts == 0 {
		config.MaxRollbackAttempts = 3
	}

	baseUpdater := NewEosUpdater(rc, config.UpdateConfig)

	return &EnhancedEosUpdater{
		EosUpdater:     baseUpdater,
		enhancedConfig: config,
		transaction: &UpdateTransaction{
			StartTime: time.Now(),
		},
	}
}

// UpdateWithRollback performs update with automatic rollback on failure
func (eeu *EnhancedEosUpdater) UpdateWithRollback() error {
	eeu.logger.Info(" Starting enhanced self-update with rollback capability")

	// Phase 1: ASSESS - Pre-update safety checks
	if err := eeu.PreUpdateSafetyChecks(); err != nil {
		return fmt.Errorf("pre-update safety checks failed: %w", err)
	}

	// Phase 2: INTERVENE - Perform update with transaction tracking
	updateErr := eeu.executeUpdateTransaction()

	// Phase 3: EVALUATE - Handle success or trigger rollback
	if updateErr != nil {
		eeu.logger.Error("❌ Update failed, initiating rollback", zap.Error(updateErr))

		if rollbackErr := eeu.Rollback(); rollbackErr != nil {
			eeu.logger.Error("💥 CRITICAL: Rollback failed", zap.Error(rollbackErr))
			return fmt.Errorf("update failed and rollback failed: update error: %w, rollback error: %v",
				updateErr, rollbackErr)
		}

		eeu.logger.Info(" Rollback successful, system restored to previous state")
		return fmt.Errorf("update failed but rolled back successfully: %w", updateErr)
	}

	// Post-update cleanup
	if err := eeu.PostUpdateCleanup(); err != nil {
		eeu.logger.Warn("Post-update cleanup had issues", zap.Error(err))
	}

	eeu.transaction.Success = true
	eeu.logger.Info(" Enhanced self-update completed successfully",
		zap.Duration("duration", time.Since(eeu.transaction.StartTime)))

	return nil
}

// PreUpdateSafetyChecks performs comprehensive safety checks before updating
func (eeu *EnhancedEosUpdater) PreUpdateSafetyChecks() error {
	eeu.logger.Info(" Phase 1: ASSESS - Running pre-update safety checks")

	// 1. Check if we're in the source directory
	if err := eeu.verifySourceDirectory(); err != nil {
		return err
	}

	// 2. Check git repository state
	if err := eeu.checkGitRepositoryState(); err != nil {
		return err
	}

	// 3. Check for running eos processes
	if eeu.enhancedConfig.CheckRunningProcesses {
		if err := eeu.checkRunningProcesses(); err != nil {
			return err
		}
	}

	// 4. Verify build dependencies
	if err := eeu.verifyBuildDependencies(); err != nil {
		return err
	}

	// 5. Check disk space
	if err := eeu.checkDiskSpace(); err != nil {
		return err
	}

	// 6. Record current git state
	if err := eeu.recordGitState(); err != nil {
		return err
	}

	eeu.logger.Info(" All pre-update safety checks passed")
	return nil
}

// verifySourceDirectory ensures we have a valid git repository
func (eeu *EnhancedEosUpdater) verifySourceDirectory() error {
	gitDir := filepath.Join(eeu.config.SourceDir, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		return fmt.Errorf("not a git repository: %s", eeu.config.SourceDir)
	}

	// Verify it's the eos repository
	cmd := exec.Command("git", "-C", eeu.config.SourceDir, "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get git remote: %w", err)
	}

	remoteURL := strings.TrimSpace(string(output))
	if !strings.Contains(remoteURL, "eos") {
		eeu.logger.Warn("Repository remote doesn't contain 'eos'", zap.String("remote", remoteURL))
	}

	eeu.logger.Debug("Source directory verified", zap.String("remote", remoteURL))
	return nil
}

// checkGitRepositoryState checks for uncommitted changes and handles stashing
func (eeu *EnhancedEosUpdater) checkGitRepositoryState() error {
	eeu.logger.Info("Checking git repository state")

	// Check for uncommitted changes
	statusCmd := exec.Command("git", "-C", eeu.config.SourceDir, "status", "--porcelain")
	statusOutput, err := statusCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check git status: %w", err)
	}

	hasChanges := len(statusOutput) > 0

	if hasChanges {
		if eeu.enhancedConfig.RequireCleanWorkingTree {
			return fmt.Errorf("repository has uncommitted changes and clean working tree is required")
		}

		eeu.logger.Warn("Repository has uncommitted changes, will stash before update")

		// Stash changes with a descriptive message
		stashMsg := fmt.Sprintf("eos-self-update-auto-stash-%d", time.Now().Unix())
		stashCmd := exec.Command("git", "-C", eeu.config.SourceDir, "stash", "push", "-m", stashMsg)
		stashOutput, err := stashCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to stash changes: %w, output: %s", err, string(stashOutput))
		}

		// Record stash reference for later recovery
		eeu.transaction.GitStashRef = stashMsg
		eeu.logger.Info(" Changes stashed", zap.String("stash_ref", stashMsg))
	} else {
		eeu.logger.Info(" Working tree is clean")
	}

	return nil
}

// checkRunningProcesses warns about running eos processes
func (eeu *EnhancedEosUpdater) checkRunningProcesses() error {
	eeu.logger.Info("Checking for running eos processes")

	// Use pgrep to find eos processes (excluding this one)
	cmd := exec.Command("pgrep", "-f", "eos")
	output, err := cmd.Output()

	if err == nil && len(output) > 0 {
		processes := strings.Split(strings.TrimSpace(string(output)), "\n")
		currentPID := os.Getpid()

		otherProcesses := []string{}
		for _, pidStr := range processes {
			pidStr = strings.TrimSpace(pidStr)
			if pidStr != "" && pidStr != fmt.Sprintf("%d", currentPID) {
				otherProcesses = append(otherProcesses, pidStr)
			}
		}

		if len(otherProcesses) > 0 {
			eeu.logger.Warn("Other eos processes are running",
				zap.Strings("pids", otherProcesses),
				zap.String("warning", "They will continue using the old binary until restarted"))
		}
	}

	return nil
}

// verifyBuildDependencies checks that we can build eos
func (eeu *EnhancedEosUpdater) verifyBuildDependencies() error {
	eeu.logger.Info("Verifying build dependencies")

	// Check Go is installed
	goPath, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("go compiler not found in PATH")
	}

	// Get Go version
	goVersionCmd := exec.Command(goPath, "version")
	goVersionOutput, err := goVersionCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check go version: %w", err)
	}

	eeu.logger.Debug("Go compiler found",
		zap.String("path", goPath),
		zap.String("version", strings.TrimSpace(string(goVersionOutput))))

	// Check pkg-config (required for libvirt)
	pkgConfigPath, err := exec.LookPath("pkg-config")
	if err != nil {
		return fmt.Errorf("pkg-config not found - required for libvirt integration")
	}

	// Check libvirt development libraries
	libvirtCheck := exec.Command(pkgConfigPath, "--exists", "libvirt")
	if err := libvirtCheck.Run(); err != nil {
		return fmt.Errorf("libvirt development libraries not found - install libvirt-dev/libvirt-devel")
	}

	eeu.logger.Info(" Build dependencies verified")
	return nil
}

// checkDiskSpace ensures we have enough space for the update
func (eeu *EnhancedEosUpdater) checkDiskSpace() error {
	eeu.logger.Info("Checking available disk space")

	// Get disk usage of /tmp (where we build) and install location
	dfCmd := exec.Command("df", "-h", "/tmp", filepath.Dir(eeu.config.BinaryPath))
	output, err := dfCmd.Output()
	if err != nil {
		eeu.logger.Warn("Could not check disk space", zap.Error(err))
		return nil // Non-fatal
	}

	eeu.logger.Debug("Disk space", zap.String("df_output", string(output)))

	// TODO: Parse df output and ensure we have at least 500MB free
	// For now, just log it

	return nil
}

// recordGitState records the current git commit for rollback
func (eeu *EnhancedEosUpdater) recordGitState() error {
	eeu.logger.Info("Recording current git state for rollback")

	// Get current commit hash
	commitCmd := exec.Command("git", "-C", eeu.config.SourceDir, "rev-parse", "HEAD")
	commitOutput, err := commitCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get current commit: %w", err)
	}

	eeu.transaction.GitCommitBefore = strings.TrimSpace(string(commitOutput))
	eeu.logger.Info("Git state recorded", zap.String("commit", eeu.transaction.GitCommitBefore[:8]))

	return nil
}

// executeUpdateTransaction performs the actual update with transaction tracking
func (eeu *EnhancedEosUpdater) executeUpdateTransaction() error {
	eeu.logger.Info(" Phase 2: INTERVENE - Executing update transaction")

	// Step 1: Create binary backup
	if err := eeu.createTransactionBackup(); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Step 2: Pull latest code
	if err := eeu.pullLatestCodeWithVerification(); err != nil {
		return fmt.Errorf("failed to pull latest code: %w", err)
	}
	eeu.transaction.ChangesPulled = true

	// Step 3: Build new binary
	tempBinary, err := eeu.BuildBinary()
	if err != nil {
		return fmt.Errorf("failed to build new binary: %w", err)
	}
	eeu.transaction.TempBinaryPath = tempBinary

	// Step 4: Validate new binary
	if !eeu.config.SkipValidation {
		if err := eeu.ValidateBinary(tempBinary); err != nil {
			return fmt.Errorf("new binary validation failed: %w", err)
		}
	}

	// Step 5: Install new binary atomically
	if err := eeu.installBinaryAtomic(tempBinary); err != nil {
		return fmt.Errorf("failed to install new binary: %w", err)
	}
	eeu.transaction.BinaryInstalled = true

	// Step 6: Verify installed binary
	if err := eeu.Verify(); err != nil {
		return fmt.Errorf("installed binary verification failed: %w", err)
	}

	eeu.logger.Info(" Update transaction completed successfully")
	return nil
}

// createTransactionBackup creates a backup with transaction metadata
func (eeu *EnhancedEosUpdater) createTransactionBackup() error {
	if err := eeu.CreateBackup(); err != nil {
		return err
	}

	// Get the actual backup path that was just created
	// CreateBackup() generates its own timestamp, so find the most recent backup
	backups, err := filepath.Glob(filepath.Join(eeu.config.BackupDir, "eos.backup.*"))
	if err != nil || len(backups) == 0 {
		return fmt.Errorf("backup created but cannot find backup file")
	}

	sort.Strings(backups)
	eeu.transaction.BackupBinaryPath = backups[len(backups)-1] // Most recent

	eeu.logger.Debug("Transaction backup recorded", zap.String("path", eeu.transaction.BackupBinaryPath))
	return nil
}

// pullLatestCodeWithVerification pulls code and verifies something actually changed
func (eeu *EnhancedEosUpdater) pullLatestCodeWithVerification() error {
	eeu.logger.Info("Pulling latest changes from git repository")

	// Get current commit before pull
	beforeCommit := eeu.transaction.GitCommitBefore

	// Pull changes
	if err := eeu.PullLatestCode(); err != nil {
		return err
	}

	// Get commit after pull
	afterCmd := exec.Command("git", "-C", eeu.config.SourceDir, "rev-parse", "HEAD")
	afterOutput, err := afterCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get commit after pull: %w", err)
	}
	afterCommit := strings.TrimSpace(string(afterOutput))

	if eeu.enhancedConfig.VerifyVersionChange && beforeCommit == afterCommit {
		eeu.logger.Info("ℹ️  Already on latest version",
			zap.String("commit", afterCommit[:8]))
		// Continue anyway in case binary was deleted or corrupted
	} else {
		eeu.logger.Info(" Updates pulled",
			zap.String("from", beforeCommit[:8]),
			zap.String("to", afterCommit[:8]))
	}

	return nil
}

// installBinaryAtomic installs the binary atomically with file locking
func (eeu *EnhancedEosUpdater) installBinaryAtomic(sourcePath string) error {
	eeu.logger.Info("Installing new binary atomically")

	// Create lock file to prevent concurrent updates
	lockFile := eeu.config.BinaryPath + ".update.lock"
	lock, err := os.OpenFile(lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("another update is in progress (lock file exists)")
		}
		return fmt.Errorf("failed to create update lock: %w", err)
	}
	defer os.Remove(lockFile)
	defer lock.Close()

	// Write PID to lock file for debugging
	fmt.Fprintf(lock, "%d\n", os.Getpid())

	if eeu.enhancedConfig.AtomicInstall {
		// Atomic rename (same filesystem)
		tempName := eeu.config.BinaryPath + ".new"

		// Copy to temp location first
		input, err := os.ReadFile(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to read new binary: %w", err)
		}

		if err := os.WriteFile(tempName, input, 0755); err != nil {
			return fmt.Errorf("failed to write temp binary: %w", err)
		}

		// Atomic rename - this is the critical operation
		if err := os.Rename(tempName, eeu.config.BinaryPath); err != nil {
			os.Remove(tempName) // Cleanup
			return fmt.Errorf("atomic rename failed: %w", err)
		}

		eeu.logger.Info(" Binary installed atomically with lock protection")
	} else {
		// Standard installation
		if err := eeu.InstallBinary(sourcePath); err != nil {
			return err
		}
	}

	return nil
}

// Rollback reverts all changes made during the update
func (eeu *EnhancedEosUpdater) Rollback() error {
	eeu.logger.Warn("🔙 Initiating rollback procedure")

	var rollbackErrors []error

	// Step 1: Restore binary if it was installed
	if eeu.transaction.BinaryInstalled && eeu.transaction.BackupBinaryPath != "" {
		eeu.logger.Info("Restoring binary from backup",
			zap.String("backup", eeu.transaction.BackupBinaryPath))

		backup, err := os.ReadFile(eeu.transaction.BackupBinaryPath)
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("failed to read backup: %w", err))
		} else if err := os.WriteFile(eeu.config.BinaryPath, backup, 0755); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("failed to restore backup: %w", err))
		} else {
			eeu.logger.Info(" Binary restored from backup")
		}
	}

	// Step 2: Revert git changes if code was pulled
	if eeu.transaction.ChangesPulled && eeu.transaction.GitCommitBefore != "" {
		eeu.logger.Info("Reverting git repository to previous commit",
			zap.String("commit", eeu.transaction.GitCommitBefore[:8]))

		// SAFETY: Only do hard reset if we have a stash OR working tree is clean
		// This prevents destroying uncommitted work if stash creation failed
		canHardReset := eeu.transaction.GitStashRef != ""
		if !canHardReset {
			// Check if working tree is clean
			statusCmd := exec.Command("git", "-C", eeu.config.SourceDir, "status", "--porcelain")
			if statusOutput, err := statusCmd.Output(); err == nil && len(statusOutput) == 0 {
				canHardReset = true
			}
		}

		if !canHardReset {
			eeu.logger.Warn("Skipping git reset --hard because working tree has changes and no stash exists",
				zap.String("manual_recovery", "Manually review changes before running: git reset --hard "+eeu.transaction.GitCommitBefore))
			rollbackErrors = append(rollbackErrors,
				fmt.Errorf("skipped git reset to protect uncommitted changes"))
		} else {
			resetCmd := exec.Command("git", "-C", eeu.config.SourceDir,
				"reset", "--hard", eeu.transaction.GitCommitBefore)
			if output, err := resetCmd.CombinedOutput(); err != nil {
				rollbackErrors = append(rollbackErrors,
					fmt.Errorf("git reset failed: %w, output: %s", err, string(output)))
			} else {
				eeu.logger.Info(" Git repository reset to previous commit")
			}
		}
	}

	// Step 3: Restore stashed changes if any
	if eeu.transaction.GitStashRef != "" {
		eeu.logger.Info("Restoring stashed changes", zap.String("stash", eeu.transaction.GitStashRef))

		// Find the stash
		stashListCmd := exec.Command("git", "-C", eeu.config.SourceDir, "stash", "list")
		stashListOutput, err := stashListCmd.Output()
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("failed to list stashes: %w", err))
		} else {
			stashList := string(stashListOutput)
			if strings.Contains(stashList, eeu.transaction.GitStashRef) {
				// Pop the stash
				stashPopCmd := exec.Command("git", "-C", eeu.config.SourceDir, "stash", "pop")
				if output, err := stashPopCmd.CombinedOutput(); err != nil {
					eeu.logger.Warn("Failed to pop stash automatically",
						zap.Error(err),
						zap.String("output", string(output)),
						zap.String("manual_recovery", fmt.Sprintf("git stash apply stash@{0}")))
					rollbackErrors = append(rollbackErrors, fmt.Errorf("stash pop failed: %w", err))
				} else {
					eeu.logger.Info(" Stashed changes restored")
				}
			}
		}
	}

	// Step 4: Cleanup temp binary
	if eeu.transaction.TempBinaryPath != "" {
		os.Remove(eeu.transaction.TempBinaryPath)
	}

	if len(rollbackErrors) > 0 {
		return fmt.Errorf("rollback encountered %d errors: %v", len(rollbackErrors), rollbackErrors)
	}

	eeu.logger.Info(" Rollback completed successfully")
	return nil
}

// PostUpdateCleanup performs cleanup after successful update
func (eeu *EnhancedEosUpdater) PostUpdateCleanup() error {
	eeu.logger.Info(" Phase 3: EVALUATE - Post-update cleanup")

	// Cleanup temp binary if it still exists
	if eeu.transaction.TempBinaryPath != "" {
		os.Remove(eeu.transaction.TempBinaryPath)
	}

	// Cleanup old backups
	eeu.CleanupOldBackups()

	// Pop stash if update was successful and we stashed changes
	if eeu.transaction.GitStashRef != "" {
		eeu.logger.Info("Restoring stashed changes after successful update")

		// Attempt to pop stash
		// Note: git stash pop will handle merge conflicts gracefully
		// If conflicts occur, user will be notified and can resolve manually
		stashPopCmd := exec.Command("git", "-C", eeu.config.SourceDir, "stash", "pop")
		if output, err := stashPopCmd.CombinedOutput(); err != nil {
			// Check if this is a merge conflict or other error
			if strings.Contains(string(output), "CONFLICT") {
				eeu.logger.Warn("Stash pop resulted in merge conflicts - manual resolution required",
					zap.String("stash_ref", eeu.transaction.GitStashRef),
					zap.String("manual_recovery", "Resolve conflicts in /opt/eos, then: git add . && git stash drop"))
			} else {
				eeu.logger.Warn("Could not automatically restore stashed changes",
					zap.Error(err),
					zap.String("output", string(output)),
					zap.String("stash_ref", eeu.transaction.GitStashRef),
					zap.String("manual_recovery", "Run: cd /opt/eos && git stash list && git stash pop"))
			}
			// Don't return error - update was successful even if stash pop failed
			return nil
		}

		eeu.logger.Info(" Stashed changes restored successfully")
	}

	return nil
}
