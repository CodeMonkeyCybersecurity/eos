// cmd/self/self.go

package self

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/enrollment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	// SelfCmd is the root command for self-management commands
	SelfCmd = &cobra.Command{
		Use:   "self",
		Short: "Self-management commands for Eos",
		Long: `The self command provides utilities for managing the Eos installation itself,
including telemetry, authentication, environment defaults, and other Eos behaviors.`,
	}

	// UpdateCmd updates Eos to the latest version
	UpdateCmd = &cobra.Command{
		Use:   "update",
		Short: "Update Eos to the latest version",
		RunE:  eos.Wrap(updateEos),
	}

	// EnrollCmd handles system enrollment into Eos infrastructure
	EnrollCmd = &cobra.Command{
		Use:   "enroll",
		Short: "Enroll system into eos/ infrastructure",
		Long: `Enroll this system into the eos/ infrastructure and handle the transition
from masterless mode to a fully managed node.`,
		RunE: eos.Wrap(enrollSystem),
	}
)

func init() {
	// Add subcommands to SelfCmd
	SelfCmd.AddCommand(UpdateCmd)
	SelfCmd.AddCommand(EnrollCmd)

	// Setup EnrollCmd flags
	setupEnrollFlags()
}

// setupEnrollFlags configures flags for the enroll command
func setupEnrollFlags() {
	EnrollCmd.Flags().String("datacenter", "", "Datacenter identifier (prompted if not provided)")
	EnrollCmd.Flags().String("network-mode", "direct", "Network mode: direct, consul-connect, or wireguard")
	EnrollCmd.Flags().Bool("auto-detect", false, "Auto-detect role based on infrastructure")
	EnrollCmd.Flags().Bool("transition-mode", false, "Force transition from masterless mode")
	EnrollCmd.Flags().Bool("dry-run", false, "Preview changes without applying them")
}

// enrollSystem handles the system enrollment process
func enrollSystem(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("Starting eos self enrollment process")

	// Parse command line flags and prompt for missing required values
	config, err := enrollment.ParseEnrollmentFlagsWithPrompts(rc, cmd)
	if err != nil {
		return eos_err.NewUserError("failed to parse enrollment flags: %s", err.Error())
	}

	// Set dry-run in runtime context attributes
	if config.DryRun {
		if rc.Attributes == nil {
			rc.Attributes = make(map[string]string)
		}
		rc.Attributes["dry_run"] = "true"
		logger.Info("Running in dry-run mode - no changes will be made")
	}

	// Validate configuration
	if err := enrollment.ValidateEnrollmentConfig(config); err != nil {
		return eos_err.NewUserError("invalid enrollment configuration: %s", err.Error())
	}

	// ASSESS - System Discovery Phase
	logger.Info("Phase 1: Discovering system configuration")
	systemInfo, err := enrollment.DiscoverSystem(rc)
	if err != nil {
		return fmt.Errorf("system discovery failed: %w", err)
	}

	logger.Info("System discovered successfully",
		zap.String("hostname", systemInfo.Hostname),
		zap.String("platform", systemInfo.Platform),
		zap.Int("cpu_cores", systemInfo.CPUCores),
		zap.Int("memory_gb", systemInfo.MemoryGB))

	// Verify prerequisites
	if err := enrollment.VerifyPrerequisites(rc, systemInfo); err != nil {
		return fmt.Errorf("prerequisite verification failed: %w", err)
	}

	// Auto-detect role if requested
	if config.AutoDetect {
		logger.Info("Auto-detecting role based on system characteristics")
		detectedRole, err := enrollment.DetectRole(rc, systemInfo)
		if err != nil {
			return fmt.Errorf("role auto-detection failed: %w", err)
		}
		config.Role = detectedRole
		logger.Info("Role detected", zap.String("role", detectedRole))
	}

	// Create backup before making changes
	logger.Info("Creating backup of current configuration")
	if err := enrollment.CreateInventoryBackup(rc); err != nil {
		logger.Warn("Failed to create backup", zap.Error(err))
	}

	// INTERVENE - Configuration Phase
	logger.Info("Phase 2: Configuring system for enrollment")

	// Validate network requirements
	if err := enrollment.ValidateNetworkRequirements(rc, config, systemInfo); err != nil {
		return fmt.Errorf("network validation failed: %w", err)
	}

	// Setup network configuration
	logger.Info("Setting up network configuration")
	if err := enrollment.SetupNetwork(rc, config, systemInfo); err != nil {
		return fmt.Errorf("network setup failed: %w", err)
	}

	// EVALUATE - Verification Phase
	logger.Info("Phase 3: Verifying enrollment")

	// Verify enrollment
	if err := enrollment.VerifyEnrollment(rc, config); err != nil {
		return fmt.Errorf("enrollment verification failed: %w", err)
	}

	// Export system information
	logger.Info("Exporting system information to inventory")
	if err := enrollment.ExportToEosInventory(rc, systemInfo); err != nil {
		return fmt.Errorf("inventory export failed: %w", err)
	}

	// Validate HashiCorp configuration export
	if err := enrollment.ValidateHashiCorpExport(rc, systemInfo); err != nil {
		logger.Warn("HashiCorp configuration validation failed", zap.Error(err))
	}

	// Generate final report
	reportStr, err := enrollment.GenerateHashiCorpVerificationReport(rc, systemInfo, config.Role)
	if err != nil {
		logger.Warn("Failed to generate verification report", zap.Error(err))
	} else {
		// Create EnrollmentResult for logging
		result := &enrollment.EnrollmentResult{
			Success:        true,
			Role:           config.Role,
			Duration:       time.Since(startTime),
			ServicesSetup:  []string{"HashiCorp Stack"},
			ConfigsUpdated: []string{"Consul", "Nomad", "Vault"},
		}
		enrollment.LogEnrollmentResults(logger, result)
		logger.Info("Verification report generated", zap.String("report", reportStr))
	}

	duration := time.Since(startTime)
	logger.Info("Eos self enrollment completed successfully",
		zap.String("role", config.Role),
		zap.String("datacenter", config.Datacenter),
		zap.Duration("duration", duration))

	return nil
}

// cleanupOldBackups removes old backup files, keeping only the most recent 3
func cleanupOldBackups(logger otelzap.LoggerWithCtx) {
	backupFiles, err := filepath.Glob("/usr/local/bin/eos.backup.*")
	if err != nil || len(backupFiles) <= 3 {
		return
	}

	// Sort by name (which includes timestamp)
	sort.Strings(backupFiles)

	// Remove all but the last 3
	for i := 0; i < len(backupFiles)-3; i++ {
		if err := os.Remove(backupFiles[i]); err == nil {
			logger.Debug("Removed old backup",
				zap.String("file", backupFiles[i]))
		}
	}
}

func updateEos(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check current state
	logger.Info("ASSESS: Checking current system state for self-update")

	// Check if we're in the correct directory
	if _, err := os.Stat("/opt/eos/.git"); os.IsNotExist(err) {
		return fmt.Errorf("EOS source directory not found at /opt/eos - cannot self-update")
	}

	// Create backup of current binary before update
	backupPath := fmt.Sprintf("/usr/local/bin/eos.backup.%d", time.Now().Unix())
	currentBinary, err := os.ReadFile("/usr/local/bin/eos")
	if err != nil {
		logger.Warn("Could not read current binary for backup",
			zap.Error(err))
	} else {
		if err := os.WriteFile(backupPath, currentBinary, 0755); err != nil {
			logger.Warn("Could not create backup",
				zap.String("backup_path", backupPath),
				zap.Error(err))
		} else {
			logger.Info("Created backup of current binary",
				zap.String("backup_path", backupPath),
				zap.Int("size_bytes", len(currentBinary)))
			// Clean up old backups (keep only last 3)
			cleanupOldBackups(logger)
		}
	}

	// INTERVENE - Pull latest code
	logger.Info("INTERVENE: Pulling latest changes from git repository")
	updateCmd := exec.Command("git", "-C", "/opt/eos", "pull", "origin", "main")
	gitOutput, err := updateCmd.CombinedOutput()
	if err != nil {
		logger.Error("Git pull failed",
			zap.Error(err),
			zap.String("output", string(gitOutput)))
		return fmt.Errorf("failed to pull latest code from GitHub: %w", err)
	}

	logger.Info("Git pull completed",
		zap.String("output", strings.TrimSpace(string(gitOutput))))

	// Detect the current system architecture
	detectCmd := exec.Command("go", "env", "GOOS", "GOARCH")
	detectOutput, err := detectCmd.Output()
	if err != nil {
		logger.Warn("Could not detect system architecture",
			zap.Error(err))
		// Continue anyway, Go will use defaults
	}

	// Build to a temporary location first to avoid corrupting the running binary
	tempBinary := fmt.Sprintf("/tmp/eos-update-%d", time.Now().Unix())
	logger.Info("Building Eos binary",
		zap.String("temp_path", tempBinary),
		zap.String("source_dir", "/opt/eos"))

	// Libvirt is now a required dependency for Eos
	// Verify pkg-config and libvirt are available
	pkgConfigPath, err := exec.LookPath("pkg-config")
	if err != nil {
		return fmt.Errorf("pkg-config not found in PATH - required for building Eos with libvirt: %w", err)
	}

	pkgConfigCmd := exec.Command(pkgConfigPath, "--exists", "libvirt")
	if err := pkgConfigCmd.Run(); err != nil {
		return fmt.Errorf("libvirt development libraries not found - install libvirt-dev/libvirt-devel: %w", err)
	}

	logger.Info("Libvirt development libraries detected - building Eos with KVM support",
		zap.String("pkg_config_path", pkgConfigPath))

	// Build command - CGO is required for libvirt
	buildArgs := []string{"build", "-o", tempBinary, "."}

	buildCmd := exec.Command("go", buildArgs...)
	buildCmd.Dir = "/opt/eos"

	// Set build environment to match current system - CGO must be enabled for libvirt
	buildCmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"GO111MODULE=on",
	)

	// If we successfully detected architecture, log it
	if detectOutput != nil {
		arch := strings.TrimSpace(string(detectOutput))
		parts := strings.Split(arch, "\n")
		if len(parts) >= 2 {
			logger.Info("Building for architecture",
				zap.String("os", strings.TrimSpace(parts[0])),
				zap.String("arch", strings.TrimSpace(parts[1])))
		}
	}

	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		logger.Error("Build failed",
			zap.Error(err),
			zap.String("output", string(buildOutput)))
		_ = os.Remove(tempBinary)
		return fmt.Errorf("failed to build Eos binary: %w", err)
	}

	// Validate the binary was created and is valid
	binaryInfo, err := os.Stat(tempBinary)
	if err != nil {
		return fmt.Errorf("built binary does not exist at %s: %w", tempBinary, err)
	}

	// Check the file size is reasonable (at least 1MB for a Go binary)
	const minBinarySize = 1024 * 1024 // 1MB
	if binaryInfo.Size() < minBinarySize {
		_ = os.Remove(tempBinary)
		return fmt.Errorf("built binary is too small (%d bytes), expected at least %d bytes",
			binaryInfo.Size(), minBinarySize)
	}

	logger.Info("Binary built successfully",
		zap.Int64("size_bytes", binaryInfo.Size()),
		zap.String("size_human", fmt.Sprintf("%.2f MB", float64(binaryInfo.Size())/(1024*1024))))

	// Set execute permissions on the temporary binary
	if err := os.Chmod(tempBinary, 0755); err != nil {
		_ = os.Remove(tempBinary)
		return fmt.Errorf("failed to set execute permissions on temp binary: %w", err)
	}

	// First, check if it's a valid ELF binary (Linux) or Mach-O (Mac)
	fileCmd := exec.Command("file", tempBinary)
	if fileOutput, err := fileCmd.Output(); err == nil {
		fileType := strings.TrimSpace(string(fileOutput))
		logger.Info("Binary file analysis",
			zap.String("file_type", fileType))

		// Check if it's actually an executable
		if !strings.Contains(fileType, "executable") && !strings.Contains(fileType, "ELF") && !strings.Contains(fileType, "Mach-O") {
			_ = os.Remove(tempBinary)
			return fmt.Errorf("built file is not an executable binary: %s", fileType)
		}
	}

	// Test the new binary before replacing the old one
	logger.Info("EVALUATE: Testing new binary with --help flag")
	testCmd := exec.Command(tempBinary, "--help")
	testOutput, err := testCmd.CombinedOutput()

	// Log the full output for debugging
	outputStr := strings.TrimSpace(string(testOutput))
	if outputStr != "" {
		// Log first 200 chars for context
		preview := outputStr
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		logger.Debug("Binary test output preview",
			zap.String("preview", preview),
			zap.Int("total_length", len(outputStr)))
	}

	if err != nil {
		logger.Error("Binary execution failed",
			zap.Error(err),
			zap.String("binary", tempBinary),
			zap.String("output", outputStr))
		_ = os.Remove(tempBinary)

		// Provide helpful error message
		if strings.Contains(outputStr, "permission denied") {
			return fmt.Errorf("new binary cannot be executed (permission denied)")
		} else if strings.Contains(outputStr, "not found") {
			return fmt.Errorf("new binary has missing dependencies")
		} else if outputStr == "" {
			return fmt.Errorf("new binary crashed with no output: %w", err)
		} else {
			// Show actual output for debugging
			if len(outputStr) > 500 {
				outputStr = outputStr[:500] + "... (truncated)"
			}
			return fmt.Errorf("new binary validation failed: %w\nOutput: %s", err, outputStr)
		}
	}

	// Check that the output contains expected text
	if !strings.Contains(outputStr, "Eos CLI") &&
		!strings.Contains(outputStr, "Available Commands") &&
		!strings.Contains(outputStr, "Usage:") {
		logger.Error("Binary produced unexpected output",
			zap.String("output", outputStr))
		_ = os.Remove(tempBinary)

		if len(outputStr) > 500 {
			outputStr = outputStr[:500] + "... (truncated)"
		}
		return fmt.Errorf("new binary output doesn't look like Eos CLI: %s", outputStr)
	}

	logger.Info("Binary validation successful",
		zap.Bool("has_eos_cli", strings.Contains(outputStr, "Eos CLI")),
		zap.Bool("has_commands", strings.Contains(outputStr, "Available Commands")),
		zap.Bool("has_usage", strings.Contains(outputStr, "Usage:")))

	// Atomically replace the old binary with the new one
	logger.Info("Replacing old binary with new one")
	if err := os.Rename(tempBinary, "/usr/local/bin/eos"); err != nil {
		// Try to copy if rename fails (might be across filesystems)
		logger.Info("Rename failed, trying copy instead")
		input, err := os.ReadFile(tempBinary)
		if err != nil {
			_ = os.Remove(tempBinary)
			return fmt.Errorf("failed to read temp binary for copy: %w", err)
		}

		if err := os.WriteFile("/usr/local/bin/eos", input, 0755); err != nil {
			_ = os.Remove(tempBinary)
			return fmt.Errorf("failed to copy new binary to destination: %w", err)
		}

		// Clean up temp file after successful copy
		_ = os.Remove(tempBinary)
	}

	logger.Info("Binary replacement completed successfully")

	// EVALUATE - Verify the update
	logger.Info("Verifying Eos update")
	versionCmd := exec.Command("/usr/local/bin/eos", "--help")
	verifyOutput, err := versionCmd.CombinedOutput()

	if err != nil {
		logger.Warn("Could not verify Eos after update",
			zap.Error(err),
			zap.String("output", string(verifyOutput)))
	} else if strings.Contains(string(verifyOutput), "Eos CLI") || strings.Contains(string(verifyOutput), "Available Commands:") {
		logger.Info("Eos binary verified successfully")
	} else {
		logger.Warn("Eos binary verification produced unexpected output",
			zap.String("output", string(verifyOutput)))
	}

	logger.Info("EVALUATE: Self-update completed successfully")
	return nil
}
