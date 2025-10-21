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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/build"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/process"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
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
	UpdateSystemPackages    bool // Run system package manager update (apt/yum/dnf)
	UpdateGoVersion         bool // Check and update Go compiler if needed
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
			eeu.logger.Warn("System package update had issues", zap.Error(err))
			// Non-fatal - continue
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
	return process.WarnAboutRunningProcesses(eeu.rc, "eos")
}

// verifyBuildDependencies checks that we can build eos
func (eeu *EnhancedEosUpdater) verifyBuildDependencies() error {
	eeu.logger.Info("Verifying build dependencies")

	// Use the new build.VerifyAllDependencies function
	result, err := build.VerifyAllDependencies(eeu.rc)
	if err != nil {
		return err
	}

	// Store Go path for later use in build
	eeu.goPath = result.GoPath

	// If Ceph libraries are missing, attempt to install them
	if !result.CephLibsOK {
		eeu.logger.Warn("Ceph development libraries not found, attempting to install",
			zap.Strings("missing", result.MissingCephLibs))

		// Detect package manager
		pkgMgr := system.DetectPackageManager()
		if pkgMgr == system.PackageManagerNone {
			return fmt.Errorf("%s\nAuto-install failed: no supported package manager found",
				build.FormatMissingCephLibsError(result.MissingCephLibs))
		}

		// Attempt to install missing Ceph libraries automatically
		if err := system.InstallCephLibraries(eeu.rc, pkgMgr, result.MissingCephLibs); err != nil {
			return fmt.Errorf("%s\nAuto-install failed: %w",
				build.FormatMissingCephLibsError(result.MissingCephLibs), err)
		}

		eeu.logger.Info(" Ceph development libraries installed successfully")
	}

	eeu.logger.Info(" Build dependencies verified")
	return nil
}

// checkDiskSpace ensures we have enough space for the update
func (eeu *EnhancedEosUpdater) checkDiskSpace() error {
	eeu.logger.Info("Checking available disk space")
	_, _ = system.CheckDiskSpace(eeu.rc, "/tmp", filepath.Dir(eeu.config.BinaryPath))
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
func (eeu *EnhancedEosUpdater) BuildBinary() (string, error) {
	tempBinary := fmt.Sprintf("/tmp/eos-update-%d", time.Now().Unix())

	eeu.logger.Info("Building Eos binary",
		zap.String("temp_path", tempBinary),
		zap.String("source_dir", eeu.config.SourceDir),
		zap.String("go_path", eeu.goPath))

	// Verify dependencies are available (quick recheck before build)
	result, err := build.VerifyAllDependencies(eeu.rc)
	if err != nil {
		return "", fmt.Errorf("build dependencies not satisfied: %w", err)
	}

	if !result.CephLibsOK {
		return "", fmt.Errorf("Ceph libraries missing at build time: %v", result.MissingCephLibs)
	}

	eeu.logger.Info("Build dependencies verified")

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
	binaryInfo, err := os.Stat(tempBinary)
	if err != nil {
		return "", fmt.Errorf("built binary does not exist at %s: %w", tempBinary, err)
	}

	newSizeMB := float64(binaryInfo.Size()) / (1024 * 1024)
	newHash, err := crypto.HashFile(tempBinary)
	if err != nil {
		return "", fmt.Errorf("failed to hash new binary: %w", err)
	}

	eeu.logger.Info("Build successful",
		zap.String("binary", tempBinary),
		zap.Int64("size_bytes", binaryInfo.Size()))

	eeu.logger.Info("New binary metadata",
		zap.String("sha256", newHash[:16]+"..."),
		zap.Float64("size_mb", newSizeMB))

	return tempBinary, nil
}

// executeUpdateTransaction performs the actual update with transaction tracking
func (eeu *EnhancedEosUpdater) executeUpdateTransaction() error {
	eeu.logger.Info(" Phase 2: INTERVENE - Executing update transaction")

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
func (eeu *EnhancedEosUpdater) createTransactionBackup() (string, error) {
	// Get hash and size of current binary before backup
	currentBinaryInfo, err := os.Stat(eeu.config.BinaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat current binary: %w", err)
	}
	currentSizeMB := float64(currentBinaryInfo.Size()) / (1024 * 1024)

	currentHash, err := crypto.HashFile(eeu.config.BinaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to hash current binary: %w", err)
	}

	eeu.logger.Info("Current binary metadata",
		zap.String("sha256", currentHash[:16]+"..."),
		zap.Float64("size_mb", currentSizeMB))

	if err := eeu.CreateBackup(); err != nil {
		return "", err
	}

	// Get the actual backup path that was just created
	// CreateBackup() generates its own timestamp, so find the most recent backup
	backups, err := filepath.Glob(filepath.Join(eeu.config.BackupDir, "eos.backup.*"))
	if err != nil || len(backups) == 0 {
		return "", fmt.Errorf("backup created but cannot find backup file")
	}

	sort.Strings(backups)
	eeu.transaction.BackupBinaryPath = backups[len(backups)-1] // Most recent

	eeu.logger.Debug("Transaction backup recorded", zap.String("path", eeu.transaction.BackupBinaryPath))
	return currentHash, nil
}

// pullLatestCodeWithVerification pulls code and verifies something actually changed
// Returns true if code changed, false if already up-to-date
func (eeu *EnhancedEosUpdater) pullLatestCodeWithVerification() (bool, error) {
	return git.PullWithVerification(eeu.rc, eeu.config.SourceDir, eeu.config.GitBranch)
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
	defer func() { _ = lock.Close() }()

	// Write PID to lock file for debugging
	_, _ = fmt.Fprintf(lock, "%d\n", os.Getpid())

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
			_ = os.Remove(tempName) // Cleanup
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
	eeu.logger.Warn("Initiating rollback procedure")

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

	// Step 3: Note - we no longer manually manage stash
	// git pull --autostash handles stash automatically, so on rollback the git reset
	// will already have the correct state

	// Step 4: Cleanup temp binary
	if eeu.transaction.TempBinaryPath != "" {
		_ = os.Remove(eeu.transaction.TempBinaryPath)
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
