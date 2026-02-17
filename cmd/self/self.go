// cmd/self/self.go

package self

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/self/test"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/enrollment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	selfpkg "github.com/CodeMonkeyCybersecurity/eos/pkg/self"
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
		Long: `Update Eos to the latest version from the git repository.

By default, system packages are updated. Use flags to control behavior.

Flags:
  --system-packages   Update system packages (default: true)
  --go-version        Update Go compiler to latest version
  --force-clean       Reset repository to clean state (nuclear option for broken repos)

Examples:
  eos self update                              # Update EOS binary + system packages (default)
  eos self update --system-packages=false      # Update only EOS binary
  eos self update --go-version                 # Update EOS + system packages + Go compiler
  eos self update --force-clean                # Reset repo to clean state, then update
  eos self update --system-packages=false --go-version  # Update EOS + Go compiler only`,
		RunE: eos.Wrap(updateEos),
	}

	// EnrollCmd handles system enrollment into Eos infrastructure
	EnrollCmd = &cobra.Command{
		Use:   "enroll",
		Short: "Enroll system into eos/ infrastructure",
		Long: `Enroll this system into the eos/ infrastructure and handle the transition
from masterless mode to a fully managed node.`,
		RunE: eos.Wrap(enrollSystem),
	}

	updateSystemPackages bool
	updateGoVersion      bool
	forcePackageErrors   bool
	forceClean           bool
)

func init() {
	// Add subcommands to SelfCmd
	SelfCmd.AddCommand(UpdateCmd)
	SelfCmd.AddCommand(EnrollCmd)
	SelfCmd.AddCommand(test.TestCmd)

	// Setup UpdateCmd flags
	UpdateCmd.Flags().BoolVar(&updateSystemPackages, "system-packages", true, "Update system packages (apt/yum/dnf/pacman)")
	UpdateCmd.Flags().BoolVar(&updateGoVersion, "go-version", false, "Update Go compiler to latest version")
	UpdateCmd.Flags().BoolVar(&forcePackageErrors, "force-package-errors", false, "Continue despite system package update errors (not recommended)")
	UpdateCmd.Flags().BoolVar(&forceClean, "force-clean", false, "Reset repository to clean state before update (discards local changes)")

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

func updateEos(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting Eos self-update with enhanced safety features")

	// Create enhanced updater configuration with safety features
	config := &selfpkg.EnhancedUpdateConfig{
		UpdateConfig: &selfpkg.UpdateConfig{
			SourceDir:  "/opt/eos",
			BinaryPath: "/usr/local/bin/eos",
			GitBranch:  "main",
			MaxBackups: 3,
		},
		RequireCleanWorkingTree: false, // Allow stashing
		CheckRunningProcesses:   true,  // Warn about running processes
		AtomicInstall:           true,  // Use atomic binary replacement
		VerifyVersionChange:     true,  // Check if there's actually an update
		MaxRollbackAttempts:     3,
		UpdateSystemPackages:    updateSystemPackages, // Update system packages if requested
		UpdateGoVersion:         updateGoVersion,      // Update Go version if requested
		ForcePackageErrors:      forcePackageErrors,   // Continue despite package errors (not recommended)
		ForceClean:              forceClean,           // Reset repository to clean state (nuclear option)
	}

	updater := selfpkg.NewEnhancedEosUpdater(rc, config)

	// Execute update with automatic rollback on failure
	if err := updater.UpdateWithRollback(); err != nil {
		logger.Error("Self-update failed", zap.Error(err))
		return fmt.Errorf("self-update failed: %w", err)
	}

	logger.Info(" Self-update completed successfully - please restart any running eos processes")
	return nil
}
