package self

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
	if config.GitBranch == "" {
		config.GitBranch = "main"
	}

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

// Update performs the complete Eos self-update following Assess→Intervene→Evaluate
func (eu *EosUpdater) Update() error {
	eu.logger.Info("Starting Eos self-update")

	// ASSESS
	if _, err := eu.Assess(); err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// Create backup
	if !eu.config.SkipBackup && eu.state.BinaryExists {
		if err := eu.CreateBackup(); err != nil {
			eu.logger.Warn("Failed to create backup", zap.Error(err))
		} else {
			eu.CleanupOldBackups()
		}
	}

	// INTERVENE - Pull latest code
	if err := eu.PullLatestCode(); err != nil {
		return fmt.Errorf("failed to pull latest code: %w", err)
	}

	// Build new binary
	tempBinary, err := eu.BuildBinary()
	if err != nil {
		return fmt.Errorf("failed to build binary: %w", err)
	}
	defer func() { _ = os.Remove(tempBinary) }()

	// EVALUATE - Validate and install
	if !eu.config.SkipValidation {
		if err := eu.ValidateBinary(tempBinary); err != nil {
			return fmt.Errorf("binary validation failed: %w", err)
		}
	}

	// Install new binary
	if err := eu.InstallBinary(tempBinary); err != nil {
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	// Final verification
	if err := eu.Verify(); err != nil {
		eu.logger.Warn("Post-install verification failed", zap.Error(err))
	}

	eu.logger.Info("Eos self-update completed successfully")
	return nil
}

// CreateBackup creates a backup of the current binary
func (eu *EosUpdater) CreateBackup() error {
	backupPath := fmt.Sprintf("%s/eos.backup.%d", eu.config.BackupDir, time.Now().Unix())

	eu.logger.Info("Creating backup of current binary", zap.String("backup_path", backupPath))

	currentBinary, err := os.ReadFile(eu.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to read current binary: %w", err)
	}

	if err := os.WriteFile(backupPath, currentBinary, 0755); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	eu.logger.Info("Backup created successfully",
		zap.String("backup_path", backupPath),
		zap.Int("size_bytes", len(currentBinary)))

	return nil
}

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

// PullLatestCode pulls the latest code from git
func (eu *EosUpdater) PullLatestCode() error {
	eu.logger.Info("Pulling latest changes from git repository",
		zap.String("branch", eu.config.GitBranch))

	// Use --autostash to automatically handle uncommitted changes
	// This is more reliable than manual stashing and prevents orphaned stashes
	cmd := exec.Command("git", "-C", eu.config.SourceDir, "pull", "--autostash", "origin", eu.config.GitBranch)
	output, err := cmd.CombinedOutput()
	if err != nil {
		eu.logger.Error("Git pull failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("git pull failed: %w", err)
	}

	eu.logger.Info("Git pull completed", zap.String("output", strings.TrimSpace(string(output))))
	return nil
}

// BuildBinary builds the new Eos binary to a temporary location
func (eu *EosUpdater) BuildBinary() (string, error) {
	tempBinary := fmt.Sprintf("/tmp/eos-update-%d", time.Now().Unix())

	eu.logger.Info("Building Eos binary",
		zap.String("temp_path", tempBinary),
		zap.String("source_dir", eu.config.SourceDir))

	// Verify pkg-config and libvirt are available
	pkgConfigPath, err := exec.LookPath("pkg-config")
	if err != nil {
		return "", fmt.Errorf("pkg-config not found in PATH - required for building Eos with libvirt: %w", err)
	}

	pkgConfigCmd := exec.Command(pkgConfigPath, "--exists", "libvirt")
	if err := pkgConfigCmd.Run(); err != nil {
		return "", fmt.Errorf("libvirt development libraries not found - install libvirt-dev/libvirt-devel: %w", err)
	}

	eu.logger.Info("Libvirt development libraries detected",
		zap.String("pkg_config_path", pkgConfigPath))

	// Build command - CGO is required for libvirt
	buildArgs := []string{"build", "-o", tempBinary, "."}
	buildCmd := exec.Command("go", buildArgs...)
	buildCmd.Dir = eu.config.SourceDir

	// Set build environment - CGO must be enabled for libvirt
	buildCmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"GO111MODULE=on",
	)

	// Detect and log architecture
	if detectCmd := exec.Command("go", "env", "GOOS", "GOARCH"); detectCmd != nil {
		if detectOutput, err := detectCmd.Output(); err == nil {
			arch := strings.TrimSpace(string(detectOutput))
			parts := strings.Split(arch, "\n")
			if len(parts) >= 2 {
				eu.logger.Info("Building for architecture",
					zap.String("os", strings.TrimSpace(parts[0])),
					zap.String("arch", strings.TrimSpace(parts[1])))
			}
		}
	}

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		eu.logger.Error("Build failed",
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

	// Check the file size is reasonable (at least 1MB for a Go binary)
	const minBinarySize = 1024 * 1024 // 1MB
	if binaryInfo.Size() < minBinarySize {
		_ = os.Remove(tempBinary)
		return "", fmt.Errorf("built binary is too small (%d bytes), expected at least %d bytes",
			binaryInfo.Size(), minBinarySize)
	}

	eu.logger.Info("Binary built successfully",
		zap.Int64("size_bytes", binaryInfo.Size()),
		zap.String("size_human", fmt.Sprintf("%.2f MB", float64(binaryInfo.Size())/(1024*1024))))

	// Set execute permissions
	if err := os.Chmod(tempBinary, shared.ExecutablePerm); err != nil {
		_ = os.Remove(tempBinary)
		return "", fmt.Errorf("failed to set execute permissions: %w", err)
	}

	return tempBinary, nil
}

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

		if err := os.WriteFile(eu.config.BinaryPath, input, 0755); err != nil {
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
