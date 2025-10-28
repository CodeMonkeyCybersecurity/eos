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
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/build"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/process"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
	"golang.org/x/term"
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
	UpdateSystemPackages    bool // Run system package manager update (apt/yum/dnf)
	UpdateGoVersion         bool // Check and update Go compiler if needed
	ForcePackageErrors      bool // Continue despite package manager errors (not recommended)
}

// EnhancedEosUpdater handles self-update with comprehensive error recovery
type EnhancedEosUpdater struct {
	*EosUpdater
	enhancedConfig *EnhancedUpdateConfig
	transaction    *UpdateTransaction
	goPath         string // Path to Go compiler (may not be in PATH)
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
		eeu.logger.Error(" Update failed, initiating rollback", zap.Error(updateErr))

		if rollbackErr := eeu.Rollback(); rollbackErr != nil {
			eeu.logger.Error("CRITICAL: Rollback failed", zap.Error(rollbackErr))
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

	// Update system packages if requested (default: true)
	if eeu.enhancedConfig.UpdateSystemPackages {
		eeu.logger.Info("System package updates enabled (use --system-packages=false to skip)")
		if err := eeu.UpdateSystemPackages(); err != nil {
			// P0 FIX: System package errors are now FATAL by default
			// Broken packages can prevent eos build and leave system in inconsistent state
			if !eeu.enhancedConfig.ForcePackageErrors {
				eeu.logger.Error("System package update failed", zap.Error(err))
				return fmt.Errorf("system package update failed: %w\n\n"+
					"This is a fatal error because broken packages can prevent eos from building.\n"+
					"To force update despite package errors, use: --force-package-errors\n"+
					"(Not recommended - may leave system with broken packages)", err)
			} else {
				// User explicitly forced continuation despite errors
				eeu.logger.Warn("System package update failed but continuing due to --force-package-errors",
					zap.Error(err))
				eeu.logger.Warn("⚠️  WARNING: System may have broken packages")
			}
		} else {
			eeu.logger.Info("✓ System packages updated successfully")
		}
	}

	// Update Go version if requested
	if eeu.enhancedConfig.UpdateGoVersion {
		if err := eeu.UpdateGoVersion(); err != nil {
			eeu.logger.Warn("Go version update had issues", zap.Error(err))
			// Non-fatal - continue
		}
	}

	eeu.transaction.Success = true
	eeu.logger.Info(" Enhanced self-update completed successfully",
		zap.Duration("duration", time.Since(eeu.transaction.StartTime)))

	// Display clear success summary to user
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════════")
	if eeu.transaction.BinaryInstalled {
		// Show before/after commit hashes (first 8 chars)
		afterCommit := "unknown"
		if currentCommit, err := git.GetCurrentCommit(eeu.rc, eeu.config.SourceDir); err == nil {
			afterCommit = currentCommit
		}
		if len(eeu.transaction.GitCommitBefore) >= 8 && len(afterCommit) >= 8 {
			fmt.Printf("Update complete: %s → %s\n",
				eeu.transaction.GitCommitBefore[:8],
				afterCommit[:8])
		} else {
			fmt.Println("Update complete")
		}
	} else {
		// Already on latest version
		if len(eeu.transaction.GitCommitBefore) >= 8 {
			fmt.Printf("Already on latest version: %s\n",
				eeu.transaction.GitCommitBefore[:8])
		} else {
			fmt.Println("Already on latest version")
		}
	}

	// Show what was updated
	if eeu.enhancedConfig.UpdateSystemPackages {
		fmt.Println("   System packages: Updated")
	}
	if eeu.enhancedConfig.UpdateGoVersion {
		fmt.Println("   Go compiler: Updated")
	}

	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println()
	
	// Check for running processes - use existing pattern
	if eeu.enhancedConfig.CheckRunningProcesses {
		// Use WarnAboutRunningProcesses which already checks and logs
		if err := process.WarnAboutRunningProcesses(eeu.rc, "eos"); err == nil {
			fmt.Println("")
			fmt.Println("Restart running eos processes to use new version")
		}
	}

	fmt.Println()

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
	return git.VerifyRepository(eeu.rc, eeu.config.SourceDir)
}

// checkGitRepositoryState checks for uncommitted changes
func (eeu *EnhancedEosUpdater) checkGitRepositoryState() error {
	eeu.logger.Info("Checking git repository state")

	state, err := git.CheckRepositoryState(eeu.rc, eeu.config.SourceDir)
	if err != nil {
		return fmt.Errorf("failed to check git status: %w", err)
	}

	if state.HasChanges {
		if eeu.enhancedConfig.RequireCleanWorkingTree {
			return fmt.Errorf("repository has uncommitted changes and clean working tree is required")
		}

		eeu.logger.Warn("Repository has uncommitted changes, will use git pull --autostash")
		// Note: We don't stash here - we let git pull --autostash handle it
		// This is more reliable and doesn't leave orphaned stashes
	} else {
		eeu.logger.Info(" Working tree is clean")
	}

	return nil
}

// checkRunningProcesses warns about running eos processes
func (eeu *EnhancedEosUpdater) checkRunningProcesses() error {
	eeu.logger.Info("Checking for running eos processes")

	// Use human-centric running process checker with informed consent
	return HandleRunningProcesses(eeu.rc, eeu.config.BinaryPath)
}

// verifyBuildDependencies checks that we can build eos
// HUMAN-CENTRIC: Guides user through installing missing dependencies with informed consent
func (eeu *EnhancedEosUpdater) verifyBuildDependencies() error {
	eeu.logger.Info("Verifying build dependencies")

	// Use human-centric dependency checker that guides user through installation
	installResult, err := build.CheckAndInstallDependenciesWithConsent(eeu.rc)
	if err != nil {
		return fmt.Errorf("build dependencies not satisfied: %w", err)
	}

	// Log what was installed (if anything)
	if len(installResult.Packages) > 0 {
		eeu.logger.Info("Dependencies installed during update",
			zap.Strings("packages", installResult.Packages))
	}

	// Re-verify all dependencies are now available
	result, err := build.VerifyAllDependencies(eeu.rc)
	if err != nil {
		return fmt.Errorf("build dependencies still not satisfied after installation: %w", err)
	}

	// Store Go path for later use in build
	eeu.goPath = result.GoPath

	// Final check: all dependencies must be satisfied
	if !result.CephLibsOK {
		return fmt.Errorf("Ceph libraries still missing after installation: %v\n\n"+
			"This should not happen. Please report this issue:\n"+
			"https://github.com/CodeMonkeyCybersecurity/eos/issues",
			result.MissingCephLibs)
	}

	eeu.logger.Info(" Build dependencies verified and ready")
	return nil
}

// checkDiskSpace ensures we have enough space for the update
// SECURITY CRITICAL: Prevents partial updates that corrupt system
// P0 FIX (Adversarial #4): Dynamically calculates space based on actual binary size
func (eeu *EnhancedEosUpdater) checkDiskSpace() error {
	eeu.logger.Info("Verifying disk space requirements")

	// P0 FIX: Get actual binary size for accurate space calculation
	binaryInfo, err := os.Stat(eeu.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to stat binary for disk space calculation: %w", err)
	}
	binarySize := binaryInfo.Size()
	binarySizeMB := float64(binarySize) / (1024 * 1024)

	eeu.logger.Debug("Binary size for disk space calculation",
		zap.Int64("bytes", binarySize),
		zap.Float64("mb", binarySizeMB))

	// Define space requirements based on ACTUAL binary size
	// This prevents underestimation that would cause "no space left on device" errors
	// P0 FIX: Include backup directory for filesystem boundary detection
	reqs := system.UpdateRequirementsWithBinarySize(
		"/tmp",                             // Temp directory for build
		filepath.Dir(eeu.config.BinaryPath), // Binary directory
		eeu.config.SourceDir,               // Source directory
		eeu.config.BackupDir,               // Backup directory (for filesystem detection)
		binarySize,                         // Actual binary size
	)

	// Verify disk space with enforcement
	result, err := system.VerifyDiskSpace(eeu.rc, reqs)
	if err != nil {
		return fmt.Errorf("disk space verification failed: %w", err)
	}

	// Log warnings for low (but sufficient) space
	if len(result.Warnings) > 0 {
		eeu.logger.Warn("Disk space below recommended levels",
			zap.Strings("warnings", result.Warnings))
		for _, warning := range result.Warnings {
			eeu.logger.Warn("⚠️  "+warning)
		}
	}

	eeu.logger.Info("✓ Disk space verification passed",
		zap.String("temp", system.FormatBytes(result.TempAvailable)),
		zap.String("binary", system.FormatBytes(result.BinaryAvailable)),
		zap.String("source", system.FormatBytes(result.SourceAvailable)))

	return nil
}

// recordGitState records the current git commit for rollback
func (eeu *EnhancedEosUpdater) recordGitState() error {
	eeu.logger.Info("Recording current git state for rollback")

	commitHash, err := git.GetCurrentCommit(eeu.rc, eeu.config.SourceDir)
	if err != nil {
		return fmt.Errorf("failed to get current commit: %w", err)
	}

	eeu.transaction.GitCommitBefore = commitHash
	eeu.logger.Info("Git state recorded", zap.String("commit", commitHash[:8]))

	return nil
}

// BuildBinary overrides base method to use the correct Go path
// SECURITY: Verifies build environment integrity before compiling
func (eeu *EnhancedEosUpdater) BuildBinary() (string, error) {
	tempBinary := fmt.Sprintf("/tmp/eos-update-%d", time.Now().Unix())

	eeu.logger.Info("Building Eos binary",
		zap.String("temp_path", tempBinary),
		zap.String("source_dir", eeu.config.SourceDir),
		zap.String("go_path", eeu.goPath))

	// SECURITY CHECK: Verify build environment integrity
	// This prevents supply chain attacks via compromised build tools
	integrityCheck, err := build.VerifyBuildIntegrity(eeu.rc, eeu.goPath, eeu.config.SourceDir)
	if err != nil {
		return "", fmt.Errorf("build environment integrity check failed: %w", err)
	}

	// Log any warnings from integrity check
	for _, warning := range integrityCheck.Warnings {
		eeu.logger.Warn("SECURITY WARNING", zap.String("warning", warning))
	}

	eeu.logger.Info("Build environment integrity verified")

	// Verify dependencies are available (quick recheck before build)
	result, err := build.VerifyAllDependencies(eeu.rc)
	if err != nil {
		return "", fmt.Errorf("build dependencies not satisfied: %w", err)
	}

	if !result.CephLibsOK {
		return "", fmt.Errorf("Ceph libraries missing at build time: %v", result.MissingCephLibs)
	}

	eeu.logger.Info("Build dependencies verified")

	// P0 FIX: Re-verify disk space immediately before build
	// This prevents TOCTOU vulnerability where space was consumed between initial check and now
	// P0 FIX (Adversarial #4): Use actual binary size for accurate calculation
	eeu.logger.Debug("Re-verifying disk space before build (TOCTOU prevention)")
	binaryInfo, err := os.Stat(eeu.config.BinaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat binary for disk space re-verification: %w", err)
	}
	reqs := system.UpdateRequirementsWithBinarySize(
		"/tmp",                             // Temp directory for build
		filepath.Dir(eeu.config.BinaryPath), // Binary directory
		eeu.config.SourceDir,               // Source directory
		eeu.config.BackupDir,               // Backup directory (for filesystem detection)
		binaryInfo.Size(),                  // Actual binary size
	)
	if _, err = system.VerifyDiskSpace(eeu.rc, reqs); err != nil {
		return "", fmt.Errorf("disk space insufficient at build time: %w\n\n"+
			"Space may have been consumed by other processes between initial check and build.\n"+
			"Free up space and try again.", err)
	}
	eeu.logger.Debug("Disk space re-verification passed")

	// Build command - use the Go path we found during verification
	buildArgs := []string{"build", "-o", tempBinary, "."}
	buildCmd := exec.Command(eeu.goPath, buildArgs...)
	buildCmd.Dir = eeu.config.SourceDir

	// Set build environment - CGO must be enabled for libvirt and Ceph
	buildCmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"GO111MODULE=on",
	)

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		eeu.logger.Error("Build failed",
			zap.Error(err),
			zap.String("output", string(buildOutput)))
		_ = os.Remove(tempBinary)
		return "", fmt.Errorf("build failed: %w", err)
	}

	// Validate the binary was created and is valid
	builtBinaryInfo, err := os.Stat(tempBinary)
	if err != nil {
		return "", fmt.Errorf("built binary does not exist at %s: %w", tempBinary, err)
	}

	newSizeMB := float64(builtBinaryInfo.Size()) / (1024 * 1024)
	newHash, err := crypto.HashFile(tempBinary)
	if err != nil {
		return "", fmt.Errorf("failed to hash new binary: %w", err)
	}

	eeu.logger.Info("Build successful",
		zap.String("binary", tempBinary),
		zap.Int64("size_bytes", builtBinaryInfo.Size()))

	eeu.logger.Info("New binary metadata",
		zap.String("sha256", newHash[:16]+"..."),
		zap.Float64("size_mb", newSizeMB))

	// P1 FIX (Adversarial NEW #17): Re-verify disk space with ACTUAL new binary size
	// Previous check used old binary size, but new binary might be larger
	// This is the final check before we commit to installing the new binary
	if builtBinaryInfo.Size() != binaryInfo.Size() {
		eeu.logger.Debug("New binary size differs from old, re-verifying disk space",
			zap.Int64("old_size", binaryInfo.Size()),
			zap.Int64("new_size", builtBinaryInfo.Size()))

		reqs := system.UpdateRequirementsWithBinarySize(
			"/tmp",
			filepath.Dir(eeu.config.BinaryPath),
			eeu.config.SourceDir,
			eeu.config.BackupDir,
			builtBinaryInfo.Size(), // NEW binary size
		)
		if _, err = system.VerifyDiskSpace(eeu.rc, reqs); err != nil {
			_ = os.Remove(tempBinary) // Clean up temp binary
			return "", fmt.Errorf("disk space insufficient for new binary size: %w\n\n"+
				"New binary (%s) is larger than old binary (%s).\n"+
				"Free up space and try again.",
				err, system.FormatBytes(uint64(builtBinaryInfo.Size())), system.FormatBytes(uint64(binaryInfo.Size())))
		}
		eeu.logger.Debug("Disk space re-verification passed for new binary size")
	}

	return tempBinary, nil
}

// executeUpdateTransaction performs the actual update with transaction tracking
// P0 FIX (Adversarial NEW #5): Acquire flock BEFORE any operations to prevent concurrent updates
func (eeu *EnhancedEosUpdater) executeUpdateTransaction() error {
	eeu.logger.Info(" Phase 2: INTERVENE - Executing update transaction")

	// P0 FIX: Acquire exclusive update lock BEFORE backup creation
	// This prevents concurrent updates during backup, build, and install
	// Lock is held for entire transaction and automatically released on return
	updateLock, err := AcquireUpdateLock(eeu.rc, eeu.config.BinaryPath)
	if err != nil {
		return err // Error already includes detailed message
	}
	defer updateLock.Release()
	eeu.logger.Debug("Update lock acquired - safe to proceed with transaction")

	// Step 1: Create binary backup and record current binary hash
	currentHash, err := eeu.createTransactionBackup()
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Step 2: Pull latest code
	codeChanged, err := eeu.pullLatestCodeWithVerification()
	if err != nil {
		return fmt.Errorf("failed to pull latest code: %w", err)
	}
	eeu.transaction.ChangesPulled = codeChanged

	// If no code changes, check if binary needs rebuilding
	if !codeChanged && eeu.enhancedConfig.VerifyVersionChange {
		// Verify current binary is still valid and up-to-date
		if _, err := os.Stat(eeu.config.BinaryPath); err == nil {
			eeu.logger.Info(" No code changes detected, verifying current binary")

			// Re-verify current binary hash matches what we expect
			currentVerifyHash, err := crypto.HashFile(eeu.config.BinaryPath)
			if err == nil && currentVerifyHash == currentHash {
				eeu.logger.Info(" Current binary is up-to-date, skipping rebuild",
					zap.String("sha256", currentHash[:16]+"..."))
				eeu.logger.Info("terminal prompt: ✓ Already on latest version - no rebuild needed")
				return nil
			}
		}
		eeu.logger.Info(" Current binary needs verification, proceeding with rebuild")
	}

	// Step 3: Build new binary
	eeu.logger.Info(" Building new binary from source")
	tempBinary, err := eeu.BuildBinary()
	if err != nil {
		return fmt.Errorf("failed to build new binary: %w", err)
	}
	eeu.transaction.TempBinaryPath = tempBinary

	// Step 3a: Compare new binary hash with current binary hash
	newHash, err := crypto.HashFile(tempBinary)
	if err != nil {
		return fmt.Errorf("failed to hash new binary: %w", err)
	}

	if newHash == currentHash {
		eeu.logger.Info(" New binary is identical to current binary (SHA256 match)",
			zap.String("sha256", newHash[:16]+"..."))
		eeu.logger.Info("terminal prompt: ✓ Binary unchanged - no update needed")

		// Clean up temp binary
		_ = os.Remove(tempBinary)
		return nil
	}

	eeu.logger.Info(" Binary has changed, proceeding with installation",
		zap.String("old_sha256", currentHash[:16]+"..."),
		zap.String("new_sha256", newHash[:16]+"..."))

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

// createTransactionBackup creates a backup with transaction metadata and returns current binary hash
// P0 FIX (Adversarial NEW #4): Read file ONCE to eliminate TOCTOU between HashFile and ReadFile
func (eeu *EnhancedEosUpdater) createTransactionBackup() (string, error) {
	// P0 FIX: Read binary data ONCE into memory (eliminates TOCTOU)
	// This is the ONLY read of the source binary - all subsequent operations use this data
	binaryData, err := os.ReadFile(eeu.config.BinaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to read binary for backup: %w", err)
	}

	// Calculate hash and size from in-memory data (no TOCTOU possible)
	currentHash := crypto.HashData(binaryData)
	currentSize := int64(len(binaryData))
	currentSizeMB := float64(currentSize) / (1024 * 1024)

	eeu.logger.Info("Current binary metadata",
		zap.String("sha256", currentHash[:16]+"..."),
		zap.Float64("size_mb", currentSizeMB))

	// P0 FIX: Generate deterministic backup filename and store BEFORE calling CreateBackup
	// This prevents glob-based selection from picking up wrong backup in concurrent scenarios
	timestamp := time.Now().Format("20060102-150405")
	transactionID := fmt.Sprintf("%d", time.Now().UnixNano())
	backupFilename := fmt.Sprintf("eos.backup.%s.%s", timestamp, transactionID)
	expectedBackupPath := filepath.Join(eeu.config.BackupDir, backupFilename)

	// Store backup path in transaction BEFORE creating it
	eeu.transaction.BackupBinaryPath = expectedBackupPath
	eeu.logger.Debug("Pre-allocated backup path for transaction",
		zap.String("path", expectedBackupPath))

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(eeu.config.BackupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Write backup from in-memory data (same data we hashed)
	if err := os.WriteFile(expectedBackupPath, binaryData, 0755); err != nil {
		return "", fmt.Errorf("failed to write backup file: %w", err)
	}

	// P1 FIX (Adversarial NEW #19): Explicit memory cleanup after backup write
	// NOTE: We intentionally load entire binary (134MB) into memory to prevent TOCTOU
	// Now that backup is written, release the memory immediately instead of waiting for GC
	binaryData = nil

	// Verify backup was created successfully
	backupInfo, err := os.Stat(expectedBackupPath)
	if err != nil {
		return "", fmt.Errorf("backup file not found after creation: %w", err)
	}

	if backupInfo.Size() != currentSize {
		return "", fmt.Errorf("backup size mismatch: expected %d, got %d",
			currentSize, backupInfo.Size())
	}

	// P0 FIX (Adversarial #4): Verify backup hash matches original
	// This detects silent corruption during backup write
	backupHash, err := crypto.HashFile(expectedBackupPath)
	if err != nil {
		return "", fmt.Errorf("failed to verify backup hash: %w", err)
	}

	if backupHash != currentHash {
		// Backup is corrupted - delete it and fail
		_ = os.Remove(expectedBackupPath)
		return "", fmt.Errorf("backup hash mismatch after write\n"+
			"Expected: %s\n"+
			"Got:      %s\n"+
			"Backup file deleted. This could indicate:\n"+
			"  1. Disk write error\n"+
			"  2. File system corruption\n"+
			"  3. Out of space (partial write)\n"+
			"Check disk health: sudo smartctl -a /dev/sda",
			currentHash[:16]+"...", backupHash[:16]+"...")
	}

	eeu.logger.Info("Transaction backup created and verified",
		zap.String("path", expectedBackupPath),
		zap.Float64("size_mb", float64(backupInfo.Size())/(1024*1024)),
		zap.String("sha256", currentHash[:16]+"..."))

	return currentHash, nil
}

// pullLatestCodeWithVerification pulls code and verifies something actually changed
// Returns true if code changed, false if already up-to-date
func (eeu *EnhancedEosUpdater) pullLatestCodeWithVerification() (bool, error) {
	return git.PullWithVerification(eeu.rc, eeu.config.SourceDir, eeu.config.GitBranch)
}

// installBinaryAtomic installs the binary atomically with flock-based locking
// SECURITY: Uses flock(2) for kernel-level locking that survives process crashes
func (eeu *EnhancedEosUpdater) installBinaryAtomic(sourcePath string) error {
	eeu.logger.Info("Installing new binary atomically with flock protection")

	// P0 FIX: Re-verify disk space immediately before installation
	// This prevents TOCTOU vulnerability where space was consumed between build and install
	// P0 FIX (Adversarial #4): Use actual binary size for accurate calculation
	eeu.logger.Debug("Re-verifying disk space before install (TOCTOU prevention)")
	binaryInfo, err := os.Stat(eeu.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to stat binary for disk space re-verification: %w", err)
	}
	reqs := system.UpdateRequirementsWithBinarySize(
		"/tmp",                             // Temp directory
		filepath.Dir(eeu.config.BinaryPath), // Binary directory (critical for install)
		eeu.config.SourceDir,               // Source directory
		eeu.config.BackupDir,               // Backup directory (for filesystem detection)
		binaryInfo.Size(),                  // Actual binary size
	)
	if _, err = system.VerifyDiskSpace(eeu.rc, reqs); err != nil {
		return fmt.Errorf("disk space insufficient at install time: %w\n\n"+
			"Space may have been consumed by other processes between build and install.\n"+
			"Free up space and try again.", err)
	}
	eeu.logger.Debug("Disk space re-verification passed")

	// NOTE: Update lock already acquired in executeUpdateTransaction()
	// No need to acquire again here - lock is held for entire transaction

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
		// Lock ensures no other process is updating simultaneously
		if err := os.Rename(tempName, eeu.config.BinaryPath); err != nil {
			_ = os.Remove(tempName) // Cleanup
			return fmt.Errorf("atomic rename failed: %w", err)
		}

		eeu.logger.Info(" Binary installed atomically")
	} else {
		// Standard installation
		if err := eeu.InstallBinary(sourcePath); err != nil {
			return err
		}
	}

	return nil
}

// RollbackStep represents a single rollback operation with its status
type RollbackStep struct {
	Name        string
	Description string
	Required    bool // If true, rollback fails if this step fails
	Execute     func() error
	Status      string // "pending", "success", "failed", "skipped"
	Error       error
}

// Rollback reverts all changes made during the update with all-or-nothing semantics
// SECURITY CRITICAL: Ensures system never left in inconsistent state
func (eeu *EnhancedEosUpdater) Rollback() error {
	eeu.logger.Warn("Initiating atomic rollback procedure")

	// P0 FIX (Adversarial #1): Acquire flock BEFORE rollback operations
	// This prevents race condition where concurrent update could run during rollback
	// Without this, two processes could fight over the binary during restore
	updateLock, err := AcquireUpdateLock(eeu.rc, eeu.config.BinaryPath)
	if err != nil {
		eeu.logger.Error("Cannot acquire lock for rollback - another update may be in progress",
			zap.Error(err))
		return fmt.Errorf("cannot acquire rollback lock: %w\n\n"+
			"Another eos update may be in progress.\n"+
			"Wait for it to complete before retrying.\n"+
			"If stuck, check: ps aux | grep eos", err)
	}
	defer updateLock.Release()

	eeu.logger.Debug("Rollback lock acquired - safe to proceed")

	// Define rollback steps in reverse order of operations
	steps := []RollbackStep{
		{
			Name:        "cleanup_new_temp",
			Description: "Cleanup .new temp file from failed atomic install",
			Required:    false, // Best-effort cleanup, not critical
			Execute: func() error {
				// P0 FIX: Clean up .new temp file that may have been left by failed atomic install
				tempNewPath := eeu.config.BinaryPath + ".new"
				if _, err := os.Stat(tempNewPath); err == nil {
					eeu.logger.Warn("Found stale .new temp file from failed install",
						zap.String("path", tempNewPath))
					if err := os.Remove(tempNewPath); err != nil {
						return fmt.Errorf("failed to remove .new temp file: %w", err)
					}
					eeu.logger.Info("✓ Removed stale .new temp file")
				}

				// Also check for .restore temp file from previous rollback
				tempRestorePath := eeu.config.BinaryPath + ".restore"
				if _, err := os.Stat(tempRestorePath); err == nil {
					eeu.logger.Warn("Found stale .restore temp file from failed rollback",
						zap.String("path", tempRestorePath))
					if err := os.Remove(tempRestorePath); err != nil {
						return fmt.Errorf("failed to remove .restore temp file: %w", err)
					}
					eeu.logger.Info("✓ Removed stale .restore temp file")
				}

				return nil
			},
		},
		{
			Name:        "restore_binary",
			Description: "Restore binary from backup",
			Required:    eeu.transaction.BinaryInstalled, // Only required if we installed a binary
			Execute: func() error {
				if !eeu.transaction.BinaryInstalled || eeu.transaction.BackupBinaryPath == "" {
					return nil // Nothing to rollback
				}

				eeu.logger.Info("Restoring binary from backup",
					zap.String("backup", eeu.transaction.BackupBinaryPath))

				// Verify backup exists and is readable
				backup, err := os.ReadFile(eeu.transaction.BackupBinaryPath)
				if err != nil {
					return fmt.Errorf("failed to read backup file: %w\n"+
						"Backup location: %s\n"+
						"CRITICAL: Manual intervention required to restore binary",
						err, eeu.transaction.BackupBinaryPath)
				}

				// Verify backup is executable
				if len(backup) == 0 {
					return fmt.Errorf("backup file is empty: %s\n"+
						"CRITICAL: Cannot restore from empty backup",
						eeu.transaction.BackupBinaryPath)
				}

				// Atomic write: write to temp, then rename
				tempPath := eeu.config.BinaryPath + ".restore"
				if err := os.WriteFile(tempPath, backup, 0755); err != nil {
					return fmt.Errorf("failed to write restored binary: %w", err)
				}

				if err := os.Rename(tempPath, eeu.config.BinaryPath); err != nil {
					_ = os.Remove(tempPath) // Cleanup temp file
					return fmt.Errorf("failed to install restored binary: %w", err)
				}

				// P1 FIX: Verify restored binary is executable and functional
				eeu.logger.Debug("Verifying restored binary is executable")
				testCmd := exec.Command(eeu.config.BinaryPath, "version")
				testCmd.Env = append(os.Environ(), "EOS_SKIP_UPDATE_CHECK=1") // Prevent recursion
				if output, err := testCmd.CombinedOutput(); err != nil {
					return fmt.Errorf("restored binary is not executable: %w\n"+
						"Output: %s\n"+
						"CRITICAL: Restored binary is corrupted - manual recovery required\n"+
						"Restore from: %s",
						err, string(output), eeu.transaction.BackupBinaryPath)
				}

				eeu.logger.Info("✓ Binary restored from backup and verified executable")
				return nil
			},
		},
		{
			Name:        "revert_git",
			Description: "Revert git repository to previous commit",
			Required:    eeu.transaction.ChangesPulled, // Only required if we pulled changes
			Execute: func() error {
				if !eeu.transaction.ChangesPulled || eeu.transaction.GitCommitBefore == "" {
					return nil // Nothing to rollback
				}

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
					return fmt.Errorf("cannot safely reset git repository\n"+
						"Working tree has uncommitted changes and no stash exists.\n\n"+
						"Manual recovery required:\n"+
						"  1. Review changes: git -C %s status\n"+
						"  2. Save changes: git -C %s stash\n"+
						"  3. Reset: git -C %s reset --hard %s\n\n"+
						"CRITICAL: Git repository NOT reverted to protect uncommitted work",
						eeu.config.SourceDir, eeu.config.SourceDir,
						eeu.config.SourceDir, eeu.transaction.GitCommitBefore)
				}

				// Execute git reset
				resetCmd := exec.Command("git", "-C", eeu.config.SourceDir,
					"reset", "--hard", eeu.transaction.GitCommitBefore)
				if output, err := resetCmd.CombinedOutput(); err != nil {
					return fmt.Errorf("git reset failed: %w\n"+
						"Output: %s\n"+
						"Manual recovery: git -C %s reset --hard %s",
						err, string(output), eeu.config.SourceDir, eeu.transaction.GitCommitBefore)
				}

				// Verify we're at the correct commit
				headCmd := exec.Command("git", "-C", eeu.config.SourceDir, "rev-parse", "HEAD")
				if headOutput, err := headCmd.Output(); err == nil {
					currentCommit := strings.TrimSpace(string(headOutput))
					if currentCommit != eeu.transaction.GitCommitBefore {
						// P1 FIX: Use full 40-char hashes in error messages (not truncated)
						// Prevents ambiguity in large repos where short hashes may match multiple commits
						return fmt.Errorf("git reset completed but HEAD mismatch\n"+
							"Expected: %s\n"+
							"Got: %s\n"+
							"Manual recovery: git -C %s reset --hard %s",
							eeu.transaction.GitCommitBefore, currentCommit,
							eeu.config.SourceDir, eeu.transaction.GitCommitBefore)
					}
				}

				eeu.logger.Info("✓ Git repository reset to previous commit")
				return nil
			},
		},
		{
			Name:        "cleanup_temp",
			Description: "Cleanup temporary files",
			Required:    false, // Best-effort cleanup, not critical
			Execute: func() error {
				if eeu.transaction.TempBinaryPath != "" {
					if err := os.Remove(eeu.transaction.TempBinaryPath); err != nil && !os.IsNotExist(err) {
						return fmt.Errorf("failed to remove temp binary: %w", err)
					}
					eeu.logger.Debug("Temp binary removed", zap.String("path", eeu.transaction.TempBinaryPath))
				}
				return nil
			},
		},
	}

	// Execute rollback steps with all-or-nothing semantics
	var criticalFailures []error
	var warnings []error
	successCount := 0
	requiredCount := 0

	for i := range steps {
		step := &steps[i]
		step.Status = "pending"

		// Count required steps
		if step.Required {
			requiredCount++
		}

		// Execute step
		eeu.logger.Debug("Executing rollback step",
			zap.String("step", step.Name),
			zap.String("description", step.Description),
			zap.Bool("required", step.Required))

		err := step.Execute()
		if err != nil {
			step.Status = "failed"
			step.Error = err

			if step.Required {
				// Critical failure - rollback cannot continue
				eeu.logger.Error("CRITICAL: Required rollback step failed",
					zap.String("step", step.Name),
					zap.Error(err))
				criticalFailures = append(criticalFailures, fmt.Errorf("%s: %w", step.Name, err))
			} else {
				// Non-critical failure - log warning but continue
				eeu.logger.Warn("Non-critical rollback step failed",
					zap.String("step", step.Name),
					zap.Error(err))
				warnings = append(warnings, fmt.Errorf("%s: %w", step.Name, err))
				step.Status = "skipped"
			}
		} else {
			step.Status = "success"
			if step.Required {
				successCount++
			}
			eeu.logger.Debug("Rollback step completed",
				zap.String("step", step.Name))
		}
	}

	// ATOMIC ROLLBACK: All required steps must succeed
	if len(criticalFailures) > 0 {
		eeu.logger.Error("CRITICAL: Rollback failed - system in inconsistent state",
			zap.Int("required_steps", requiredCount),
			zap.Int("successful_steps", successCount),
			zap.Int("failed_steps", len(criticalFailures)))

		// Build detailed error report
		errorReport := fmt.Sprintf("ROLLBACK FAILED - System in inconsistent state\n\n"+
			"Required steps: %d\n"+
			"Successful: %d\n"+
			"Failed: %d\n\n"+
			"Critical failures:\n",
			requiredCount, successCount, len(criticalFailures))

		for i, err := range criticalFailures {
			errorReport += fmt.Sprintf("  %d. %v\n", i+1, err)
		}

		errorReport += "\nStep status:\n"
		for _, step := range steps {
			if step.Required {
				errorReport += fmt.Sprintf("  [%s] %s: %s\n", step.Status, step.Name, step.Description)
				if step.Error != nil {
					errorReport += fmt.Sprintf("      Error: %v\n", step.Error)
				}
			}
		}

		errorReport += "\nIMPORTANT: Manual intervention may be required to restore system.\n" +
			"Contact support: security@cybermonkey.net.au"

		return fmt.Errorf("%s", errorReport)
	}

	// Report warnings for non-critical failures
	if len(warnings) > 0 {
		eeu.logger.Warn("Rollback completed with warnings",
			zap.Int("warning_count", len(warnings)))
		for _, warn := range warnings {
			eeu.logger.Warn("Non-critical rollback issue", zap.Error(warn))
		}
	}

	eeu.logger.Info("✓ Atomic rollback completed successfully",
		zap.Int("steps_completed", successCount),
		zap.Int("total_required", requiredCount))

	return nil
}

// PostUpdateCleanup performs cleanup after successful update
func (eeu *EnhancedEosUpdater) PostUpdateCleanup() error {
	eeu.logger.Info(" Phase 3: EVALUATE - Post-update cleanup")

	// Cleanup temp binary if it still exists
	if eeu.transaction.TempBinaryPath != "" {
		_ = os.Remove(eeu.transaction.TempBinaryPath)
	}

	// Cleanup old backups
	eeu.CleanupOldBackups()

	// Note: We no longer manually manage stash - git pull --autostash handles it automatically
	// This prevents orphaned stashes and merge conflicts

	return nil
}

// UpdateSystemPackages updates the system package manager (apt/yum/dnf/pacman)
func (eeu *EnhancedEosUpdater) UpdateSystemPackages() error {
	packageManager := system.DetectPackageManager()
	if packageManager == system.PackageManagerNone {
		eeu.logger.Warn("No supported package manager detected")
		return fmt.Errorf("no supported package manager found")
	}

	eeu.logger.Info("Detected package manager", zap.String("manager", string(packageManager)))

	// HUMAN-CENTRIC: Ask for consent before updating system packages
	// This can take a long time and may require reboots
	isInteractive := term.IsTerminal(int(os.Stdin.Fd()))

	if !isInteractive {
		eeu.logger.Info("Non-interactive mode - skipping system package updates",
			zap.String("reason", "requires user consent"))
		return nil
	}

	// Explain what will happen
	eeu.logger.Info("System package update available")
	fmt.Println("\nEos can update your system packages to ensure build dependencies are current.")
	fmt.Println("")
	fmt.Printf("Package manager: %s\n", packageManager)
	fmt.Println("")
	fmt.Println("This will run:")

	switch packageManager {
	case system.PackageManagerApt:
		fmt.Println("  1. sudo apt update        (refresh package lists)")
		fmt.Println("  2. sudo apt upgrade -y    (install updates)")
		fmt.Println("  3. sudo apt autoremove -y (remove old packages)")
	case system.PackageManagerYum:
		fmt.Println("  1. sudo yum update -y     (update packages)")
		fmt.Println("  2. sudo yum autoremove -y (remove old packages)")
	case system.PackageManagerDnf:
		fmt.Println("  1. sudo dnf update -y     (update packages)")
		fmt.Println("  2. sudo dnf autoremove -y (remove old packages)")
	case system.PackageManagerPacman:
		fmt.Println("  1. sudo pacman -Syu       (update packages)")
	}

	fmt.Println("")
	fmt.Println("IMPORTANT:")
	fmt.Println("  • This may take 5-30 minutes depending on your system")
	fmt.Println("  • Some updates may require a system reboot")
	fmt.Println("  • You can skip this and update packages manually later")
	fmt.Println("")

	// Ask for consent
	confirmed, err := interaction.PromptYesNoSafe(eeu.rc,
		"Update system packages now?",
		false) // Default to No for safety

	if err != nil {
		return fmt.Errorf("failed to get user consent: %w", err)
	}

	if !confirmed {
		eeu.logger.Info("User declined system package updates")
		fmt.Println("\nSkipping system package updates.")
		fmt.Println("You can update manually with:")

		switch packageManager {
		case system.PackageManagerApt:
			fmt.Println("  sudo apt update && sudo apt upgrade -y")
		case system.PackageManagerYum:
			fmt.Println("  sudo yum update -y")
		case system.PackageManagerDnf:
			fmt.Println("  sudo dnf update -y")
		case system.PackageManagerPacman:
			fmt.Println("  sudo pacman -Syu")
		}

		return nil
	}

	// User consented - proceed with update
	eeu.logger.Info("User consented to system package updates")
	fmt.Println("\nUpdating system packages...")

	return system.UpdateSystemPackages(eeu.rc, packageManager)
}

// UpdateGoVersion checks and updates the Go compiler if a newer version is available
func (eeu *EnhancedEosUpdater) UpdateGoVersion() error {
	eeu.logger.Info("Checking Go compiler version")

	// Get current Go version
	currentVersion, err := eeu.getCurrentGoVersion()
	if err != nil {
		return fmt.Errorf("failed to get current Go version: %w", err)
	}

	eeu.logger.Info("Current Go version", zap.String("version", currentVersion))

	// Get latest Go version from golang.org
	latestVersion, err := eeu.getLatestGoVersion()
	if err != nil {
		eeu.logger.Warn("Could not check for latest Go version", zap.Error(err))
		return nil // Non-fatal
	}

	eeu.logger.Info("Latest Go version", zap.String("version", latestVersion))

	// Compare versions
	if currentVersion == latestVersion {
		eeu.logger.Info(" Go compiler is already up-to-date")
		return nil
	}

	eeu.logger.Info("Newer Go version available",
		zap.String("current", currentVersion),
		zap.String("latest", latestVersion))

	// Download and install new Go version
	if err := eeu.installGoVersion(latestVersion); err != nil {
		return fmt.Errorf("failed to install Go %s: %w", latestVersion, err)
	}

	eeu.logger.Info(" Go compiler updated successfully", zap.String("version", latestVersion))
	return nil
}

// getCurrentGoVersion returns the currently installed Go version
func (eeu *EnhancedEosUpdater) getCurrentGoVersion() (string, error) {
	cmd := exec.Command(eeu.goPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse "go version go1.21.5 linux/amd64" -> "1.21.5"
	version := strings.TrimSpace(string(output))
	parts := strings.Fields(version)
	if len(parts) < 3 {
		return "", fmt.Errorf("unexpected go version output: %s", version)
	}

	// Remove "go" prefix from version
	goVersion := strings.TrimPrefix(parts[2], "go")
	return goVersion, nil
}

// getLatestGoVersion fetches the latest stable Go version from golang.org
func (eeu *EnhancedEosUpdater) getLatestGoVersion() (string, error) {
	// Use curl to get the latest version from golang.org/VERSION?m=text
	cmd := exec.Command("curl", "-s", "https://go.dev/VERSION?m=text")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest Go version: %w", err)
	}

	// Parse "go1.21.5" -> "1.21.5"
	version := strings.TrimSpace(string(output))
	lines := strings.Split(version, "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("empty response from golang.org")
	}

	latestVersion := strings.TrimPrefix(lines[0], "go")
	return latestVersion, nil
}

// installGoVersion downloads and installs a specific Go version
func (eeu *EnhancedEosUpdater) installGoVersion(version string) error {
	eeu.logger.Info("Installing Go version", zap.String("version", version))

	// Detect architecture
	arch := "amd64"
	unameMCmd := exec.Command("uname", "-m")
	if unameOutput, err := unameMCmd.Output(); err == nil {
		machine := strings.TrimSpace(string(unameOutput))
		if strings.Contains(machine, "arm") || strings.Contains(machine, "aarch64") {
			arch = "arm64"
		}
	}

	// Detect OS
	goos := "linux"
	unameCmd := exec.Command("uname", "-s")
	if unameOutput, err := unameCmd.Output(); err == nil {
		osName := strings.ToLower(strings.TrimSpace(string(unameOutput)))
		if strings.Contains(osName, "darwin") {
			goos = "darwin"
		}
	}

	filename := fmt.Sprintf("go%s.%s-%s.tar.gz", version, goos, arch)
	downloadURL := fmt.Sprintf("https://go.dev/dl/%s", filename)
	tempFile := filepath.Join("/tmp", filename)

	eeu.logger.Info("Downloading Go",
		zap.String("url", downloadURL),
		zap.String("dest", tempFile))

	// Download
	downloadCmd := exec.Command("curl", "-L", "-o", tempFile, downloadURL)
	downloadCmd.Stdout = os.Stdout
	downloadCmd.Stderr = os.Stderr

	if err := downloadCmd.Run(); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	defer os.Remove(tempFile)

	eeu.logger.Info("Installing Go to /usr/local")

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("Go installation requires root privileges - run with sudo")
	}

	// Remove old Go installation
	removeCmd := exec.Command("rm", "-rf", "/usr/local/go")
	if err := removeCmd.Run(); err != nil {
		eeu.logger.Warn("Could not remove old Go installation", zap.Error(err))
	}

	// Extract new Go
	extractCmd := exec.Command("tar", "-C", "/usr/local", "-xzf", tempFile)
	extractCmd.Stdout = os.Stdout
	extractCmd.Stderr = os.Stderr

	if err := extractCmd.Run(); err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	eeu.logger.Info(" Go installed successfully")

	// Update goPath to new installation
	eeu.goPath = "/usr/local/go/bin/go"

	return nil
}
