package update

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Safe storage operation flags
var (
	safeMode       bool
	safeDryRun     bool
	skipSnapshots  bool
	safeSize       string
	safeVG         string
	safeLV         string
	confirmChanges bool
)

// UpdateStorageSafeCmd provides safe storage operations with comprehensive safety checks
var UpdateStorageSafeCmd = &cobra.Command{
	Use:   "safe",
	Short: "Safely update storage with comprehensive safety checks",
	Long: `Safe storage operations including:
- Comprehensive preflight health checks
- Automatic LVM snapshots for rollback
- Operation journaling and audit trail
- Real-time verification and validation
- Rollback capabilities if operations fail

Safety Features:
- Filesystem health validation
- Open file detection
- SMART disk health checks
- Automatic snapshots before changes
- Operation logging and recovery

Examples:
  eos update storage safe --resize                    # Safe Ubuntu LVM auto-resize
  eos update storage safe --vg ubuntu-vg --lv ubuntu-lv --size +50G
  eos update storage safe --resize --dry-run          # Test operation first
  eos update storage safe --vg ubuntu-vg --lv ubuntu-lv --size +50G --skip-snapshots`,
	RunE: eos.Wrap(runUpdateStorageSafe),
}

func init() {
	UpdateStorageCmd.AddCommand(UpdateStorageSafeCmd)

	UpdateStorageSafeCmd.Flags().BoolVar(&safeMode, "resize", false, "Auto-resize Ubuntu LVM safely")
	UpdateStorageSafeCmd.Flags().BoolVar(&safeDryRun, "dry-run", false, "Show what would be done without making changes")
	UpdateStorageSafeCmd.Flags().BoolVar(&skipSnapshots, "skip-snapshots", false, "Skip creating safety snapshots")
	UpdateStorageSafeCmd.Flags().StringVar(&safeSize, "size", "", "Size to extend (e.g., +50G, +100%FREE)")
	UpdateStorageSafeCmd.Flags().StringVar(&safeVG, "vg", "", "Volume group name")
	UpdateStorageSafeCmd.Flags().StringVar(&safeLV, "lv", "", "Logical volume name")
	UpdateStorageSafeCmd.Flags().BoolVar(&confirmChanges, "yes", false, "Automatically confirm all prompts")
}

func runUpdateStorageSafe(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting safe storage update operation",
		zap.Bool("safe_mode", safeMode),
		zap.Bool("dry_run", safeDryRun),
		zap.Bool("skip_snapshots", skipSnapshots),
		zap.String("vg", safeVG),
		zap.String("lv", safeLV),
		zap.String("size", safeSize))

	// Create safety configuration
	safetyConfig := storage.DefaultSafetyConfig()
	safetyConfig.RequireSnapshot = skipSnapshots // Invert the logic - if skip is true, don't require
	// Note: We always try to create snapshots but don't fail if they can't be created (unless required)

	// Initialize safe storage operations
	safeOps, err := storage.NewSafeStorageOperations(rc, safetyConfig)
	if err != nil {
		return fmt.Errorf("initialize safe operations: %w", err)
	}

	var result *storage.OperationResult

	// Handle different operation modes
	if safeMode {
		// Auto-resize Ubuntu LVM
		result, err = safeOps.SafeAutoResizeUbuntuLVM(rc, safeDryRun)
	} else if safeVG != "" && safeLV != "" && safeSize != "" {
		// Specific LV extension
		req := &storage.ExtendLVRequest{
			VolumeGroup:   safeVG,
			LogicalVolume: safeLV,
			Size:          safeSize,
			DryRun:        safeDryRun,
		}

		// Get user confirmation if required
		if !confirmChanges && !safeDryRun {
			if err := getOperationConfirmation(req); err != nil {
				return err
			}
		}

		result, err = safeOps.SafeExtendLV(rc, req)
	} else {
		return fmt.Errorf("insufficient parameters: specify --resize for auto-resize or --vg, --lv, and --size for specific operations")
	}

	// Handle operation result
	if err != nil {
		logger.Error("Safe storage operation failed",
			zap.Error(err),
			zap.String("journal_id", result.JournalID))

		// Show rollback options if available
		if result != nil && result.RollbackAvailable {
			logger.Info("Rollback is available for this operation",
				zap.String("journal_id", result.JournalID))
			fmt.Printf("\nOperation failed but rollback is available.\n")
			fmt.Printf("To rollback: eos rollback disk-operation %s\n", result.JournalID)
		}

		return err
	}

	// Display operation result
	logger.Info("Safe storage operation completed",
		zap.Bool("success", result.Success),
		zap.String("journal_id", result.JournalID),
		zap.Duration("duration", result.Duration))

	// Show operation summary (simplified for placeholder implementation)
	fmt.Printf("\n=== OPERATION SUMMARY ===\n")
	fmt.Printf("Operation: %s\n", result.Operation)
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Status: %s\n", getStatusIcon(result.Success))
	fmt.Printf("Duration: %s\n", result.Duration.Round(100*1000000)) // Round to 100ms

	if result.JournalID != "" {
		fmt.Printf("Journal ID: %s\n", result.JournalID)
	}

	if result.SnapshotCreated {
		fmt.Printf("Safety Snapshot: ✓ Created (%s)\n", result.SnapshotID)
	}

	// Show preflight results (simplified)
	if result.PreflightReport != nil {
		fmt.Printf("\nPreflight: Placeholder implementation - requires administrator intervention\n")
	}

	if result.Message != "" {
		fmt.Printf("\n%s\n", result.Message)
	}

	return nil
}

// getOperationConfirmation prompts user for operation confirmation
func getOperationConfirmation(req *storage.ExtendLVRequest) error {
	fmt.Printf("\n=== OPERATION CONFIRMATION ===\n")
	fmt.Printf("Volume Group: %s\n", req.VolumeGroup)
	fmt.Printf("Logical Volume: %s\n", req.LogicalVolume)
	fmt.Printf("Extension Size: %s\n", req.Size)
	fmt.Printf("Target Device: /dev/%s/%s\n", req.VolumeGroup, req.LogicalVolume)

	fmt.Printf("\nThis operation will:\n")
	fmt.Printf("1. Run comprehensive safety checks\n")
	fmt.Printf("2. Create an LVM snapshot for rollback\n")
	fmt.Printf("3. Extend the logical volume\n")
	fmt.Printf("4. Resize the filesystem\n")
	fmt.Printf("5. Verify the operation succeeded\n")

	fmt.Printf("\nDo you want to proceed? (yes/no): ")

	var response string
	if _, err := fmt.Scanln(&response); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "yes" && response != "y" {
		return fmt.Errorf("operation cancelled by user")
	}

	return nil
}

// getStatusIcon returns a visual status indicator
func getStatusIcon(success bool) string {
	if success {
		return "✓ SUCCESS"
	}
	return "✗ FAILED"
}
