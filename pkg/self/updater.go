package self

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateConfig holds configuration for Eos self-update
type UpdateConfig struct {
	SourceDir      string
	BinaryPath     string
	BackupDir      string
	MaxBackups     int
	GitBranch      string
	SkipBackup     bool
	SkipValidation bool
}

// UpdateState represents the state of the Eos installation
type UpdateState struct {
	SourceExists   bool
	BinaryExists   bool
	GitRepository  bool
	CurrentVersion string
	SourcePath     string
	BinaryPath     string
	BackupPaths    []string
}

// EosUpdater handles Eos self-update following Assess→Intervene→Evaluate pattern
type EosUpdater struct {
	rc     *eos_io.RuntimeContext
	config *UpdateConfig
	logger otelzap.LoggerWithCtx
	state  *UpdateState
}

// NewEosUpdater creates a new Eos updater
func NewEosUpdater(rc *eos_io.RuntimeContext, config *UpdateConfig) *EosUpdater {
	// Set defaults if not provided
	if config.SourceDir == "" {
		config.SourceDir = "/opt/eos"
	}
	if config.BinaryPath == "" {
		config.BinaryPath = "/usr/local/bin/eos"
	}
	if config.BackupDir == "" {
		config.BackupDir = "/usr/local/bin"
	}
	if config.MaxBackups == 0 {
		config.MaxBackups = 3
	}
	// NOTE: GitBranch intentionally has NO default. Callers must resolve
	// the checked-out branch explicitly (see cmd/self/self.go) to prevent
	// cross-branch updates. checkGitRepositoryState enforces this at runtime.

	return &EosUpdater{
		rc:     rc,
		config: config,
		logger: otelzap.Ctx(rc.Ctx),
		state:  &UpdateState{},
	}
}

// Assess checks the current state of the Eos installation
func (eu *EosUpdater) Assess() (*UpdateState, error) {
	eu.logger.Info("Assessing Eos installation state")

	// Check if source directory exists
	gitDir := filepath.Join(eu.config.SourceDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		eu.state.SourceExists = true
		eu.state.GitRepository = true
		eu.state.SourcePath = eu.config.SourceDir
	} else if os.IsNotExist(err) {
		return nil, fmt.Errorf("EOS source directory not found at %s - cannot self-update", eu.config.SourceDir)
	}

	// Check if binary exists
	if _, err := os.Stat(eu.config.BinaryPath); err == nil {
		eu.state.BinaryExists = true
		eu.state.BinaryPath = eu.config.BinaryPath
	}

	// Find existing backups
	backupPattern := filepath.Join(eu.config.BackupDir, "eos.backup.*")
	if backups, err := filepath.Glob(backupPattern); err == nil {
		eu.state.BackupPaths = backups
	}

	eu.logger.Info("Assessment complete",
		zap.Bool("source_exists", eu.state.SourceExists),
		zap.Bool("git_repository", eu.state.GitRepository),
		zap.Bool("binary_exists", eu.state.BinaryExists),
		zap.Int("backup_count", len(eu.state.BackupPaths)))

	return eu.state, nil
}

// NOTE: The simple Update() and CreateBackup() methods were removed.
// Production code uses EnhancedEosUpdater.UpdateWithRollback() which provides
// transaction tracking, atomic rollback, and the flock-based locking lifecycle.
// See pkg/self/updater_enhanced.go.

// CleanupOldBackups removes old backup files, keeping only the most recent N
func (eu *EosUpdater) CleanupOldBackups() {
	backupFiles, err := filepath.Glob(filepath.Join(eu.config.BackupDir, "eos.backup.*"))
	if err != nil || len(backupFiles) <= eu.config.MaxBackups {
		return
	}

	// Sort by name (which includes timestamp)
	sort.Strings(backupFiles)

	// Remove all but the last N
	for i := 0; i < len(backupFiles)-eu.config.MaxBackups; i++ {
		if err := os.Remove(backupFiles[i]); err == nil {
			eu.logger.Debug("Removed old backup", zap.String("file", backupFiles[i]))
		}
	}
}

// NOTE: PullLatestCode() and the base BuildBinary() were removed.
// Production code uses EnhancedEosUpdater.pullLatestCodeWithVerification() and
// EnhancedEosUpdater.BuildBinary() which include branch safety, stash tracking,
// build integrity checks, and commit embedding.

// ValidateBinary validates that the binary is executable and works correctly
func (eu *EosUpdater) ValidateBinary(binaryPath string) error {
	eu.logger.Info("Validating new binary")

	// Check if it's a valid executable binary
	fileCmd := exec.Command("file", binaryPath)
	if fileOutput, err := fileCmd.Output(); err == nil {
		fileType := strings.TrimSpace(string(fileOutput))
		eu.logger.Info("Binary file analysis", zap.String("file_type", fileType))

		if !strings.Contains(fileType, "executable") && !strings.Contains(fileType, "ELF") && !strings.Contains(fileType, "Mach-O") {
			return fmt.Errorf("built file is not an executable binary: %s", fileType)
		}
	}

	// Test the binary with --help flag
	testCmd := exec.Command(binaryPath, "--help")
	testOutput, err := testCmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(testOutput))

	if err != nil {
		eu.logger.Error("Binary execution failed",
			zap.Error(err),
			zap.String("binary", binaryPath),
			zap.String("output", outputStr))

		// Provide helpful error message
		if strings.Contains(outputStr, "permission denied") {
			return fmt.Errorf("new binary cannot be executed (permission denied)")
		} else if strings.Contains(outputStr, "not found") {
			return fmt.Errorf("new binary has missing dependencies")
		} else if outputStr == "" {
			return fmt.Errorf("new binary crashed with no output: %w", err)
		}
		return fmt.Errorf("binary validation failed: %w", err)
	}

	// Check that the output contains expected text
	if !strings.Contains(outputStr, "Eos CLI") &&
		!strings.Contains(outputStr, "Available Commands") &&
		!strings.Contains(outputStr, "Usage:") {
		eu.logger.Error("Binary produced unexpected output", zap.String("output", outputStr))
		return fmt.Errorf("new binary output doesn't look like Eos CLI")
	}

	eu.logger.Info("Binary validation successful",
		zap.Bool("has_eos_cli", strings.Contains(outputStr, "Eos CLI")),
		zap.Bool("has_commands", strings.Contains(outputStr, "Available Commands")),
		zap.Bool("has_usage", strings.Contains(outputStr, "Usage:")))

	return nil
}

// InstallBinary atomically replaces the old binary with the new one
func (eu *EosUpdater) InstallBinary(sourcePath string) error {
	eu.logger.Info("Installing new binary", zap.String("destination", eu.config.BinaryPath))

	// Try atomic rename first
	if err := os.Rename(sourcePath, eu.config.BinaryPath); err != nil {
		// If rename fails, try copy (might be across filesystems)
		eu.logger.Debug("Rename failed, trying copy instead")

		input, err := os.ReadFile(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to read temp binary for copy: %w", err)
		}

		if err := os.WriteFile(eu.config.BinaryPath, input, shared.ExecutablePerm); err != nil {
			return fmt.Errorf("failed to copy new binary to destination: %w", err)
		}
	}

	eu.logger.Info("Binary installation completed successfully")
	return nil
}

// Verify verifies the installed binary works correctly
func (eu *EosUpdater) Verify() error {
	eu.logger.Info("Verifying installed Eos binary")

	versionCmd := exec.Command(eu.config.BinaryPath, "--help")
	verifyOutput, err := versionCmd.CombinedOutput()

	if err != nil {
		eu.logger.Warn("Could not verify Eos after update",
			zap.Error(err),
			zap.String("output", string(verifyOutput)))
		return fmt.Errorf("verification failed: %w", err)
	}

	outputStr := string(verifyOutput)
	if strings.Contains(outputStr, "Eos CLI") || strings.Contains(outputStr, "Available Commands:") {
		eu.logger.Info("Eos binary verified successfully")
		return nil
	}

	eu.logger.Warn("Eos binary verification produced unexpected output",
		zap.String("output", outputStr))
	return fmt.Errorf("unexpected output from installed binary")
}
