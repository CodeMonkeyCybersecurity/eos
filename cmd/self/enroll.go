// cmd/self/enroll.go
package self

import (
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/enrollment"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var EnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll system into eos/salt infrastructure",
	Long: `Enroll this system into the eos/salt infrastructure and handle the transition
from masterless to master/minion architecture.

This command will:
1. Discover current system configuration and resources
2. Determine the appropriate role (master or minion)
3. Configure networking (direct, consul-connect, or wireguard)
4. Install and configure Salt with the appropriate role
5. Handle transition from masterless if needed
6. Verify enrollment and export system information

Features:
  - Auto-detection of appropriate role based on system resources
  - Network mode selection (direct, consul-connect, wireguard)
  - Seamless transition from masterless to master/minion mode
  - Dry-run capability for preview
  - Automatic backup creation before changes
  - Comprehensive verification and reporting

Examples:
  # Enroll as master with specific datacenter
  eos self enroll --role=master --datacenter=us-west
  
  # Enroll as minion with master address
  eos self enroll --role=minion --master-address=10.0.1.100 --datacenter=us-west
  
  # Auto-detect role with consul network
  eos self enroll --auto-detect --network-mode=consul-connect --datacenter=us-west
  
  # Preview changes without applying
  eos self enroll --dry-run --role=master --datacenter=us-west
  
  # Force transition from masterless mode
  eos self enroll --transition-mode --role=minion --master-address=10.0.1.100 --datacenter=us-west`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		startTime := time.Now()
		
		logger.Info("Starting eos self enrollment process")
		
		// Parse command line flags
		config, err := enrollment.ParseEnrollmentFlags(cmd)
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
		
		// Handle transition from masterless if needed
		if config.TransitionMode || systemInfo.SaltMode == enrollment.SaltModeMasterless {
			logger.Info("Handling transition from masterless mode")
			if err := enrollment.TransitionFromMasterless(rc, config.MasterAddress); err != nil {
				return fmt.Errorf("masterless transition failed: %w", err)
			}
		}
		
		// Configure Salt
		logger.Info("Configuring Salt")
		if err := enrollment.ConfigureSalt(rc, config); err != nil {
			return fmt.Errorf("Salt configuration failed: %w", err)
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
		
		// Validate inventory export
		if err := enrollment.ValidateInventoryExport(rc, systemInfo); err != nil {
			logger.Warn("Inventory export validation failed", zap.Error(err))
		}
		
		// Generate final report
		result, err := enrollment.GenerateVerificationReport(rc, config, systemInfo)
		if err != nil {
			logger.Warn("Failed to generate verification report", zap.Error(err))
		} else {
			result.Duration = time.Since(startTime)
			enrollment.LogEnrollmentResults(logger, result)
		}
		
		duration := time.Since(startTime)
		logger.Info("Eos self enrollment completed successfully",
			zap.String("role", config.Role),
			zap.String("datacenter", config.Datacenter),
			zap.Duration("duration", duration))
		
		return nil
	}),
}

func init() {
	SelfCmd.AddCommand(EnrollCmd)

	// Role configuration
	EnrollCmd.Flags().String("role", "", "Salt role: master or minion (required unless --auto-detect)")
	EnrollCmd.Flags().String("master-address", "", "Salt master address (required for minion role)")
	EnrollCmd.Flags().String("datacenter", "", "Datacenter identifier (required)")

	// Network configuration
	EnrollCmd.Flags().String("network-mode", "direct", "Network mode: direct, consul-connect, or wireguard")
	
	// Enrollment options
	EnrollCmd.Flags().Bool("auto-detect", false, "Auto-detect role based on infrastructure")
	EnrollCmd.Flags().Bool("transition-mode", false, "Force transition from masterless mode")
	EnrollCmd.Flags().Bool("dry-run", false, "Preview changes without applying them")
	
	// Mark required flags
	EnrollCmd.MarkFlagRequired("datacenter")
}
// All helper functions have been migrated to pkg/enrollment/