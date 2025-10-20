//go:build linux

package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm/disk"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	diskSize       string
	diskForce      bool
	diskDryRun     bool
	diskSkipBackup bool
	diskSkipVerify bool
	diskBackupPath string
)

// UpdateKVMDiskCmd resizes KVM virtual machine disks
var UpdateKVMDiskCmd = &cobra.Command{
	Use:   "kvm-disk [vm-name]",
	Short: "Safely resize KVM virtual machine disks",
	Long: `Safely resize KVM virtual machine disks with comprehensive safety checks.

This command performs disk resize operations with full safety mechanisms:
- Automatic backup creation before changes
- Transaction logging for rollback capability
- Guest filesystem operations (when guest agent available)
- Comprehensive verification of changes

SAFETY FEATURES:
- Pre-flight assessment of VM state and risks
- Automatic backup unless --skip-backup specified
- Transaction log for every operation
- Rollback capability on failure
- Verification of resize success

IMPORTANT NOTES:
- Growing disks is generally safe
- Shrinking disks requires --force flag and is DANGEROUS
- VM should be shut off for offline resize (safest)
- Guest agent enables automatic filesystem resize
- Without guest agent, manual steps required inside guest

EXAMPLES:
  # Grow disk by 50GB (safe operation)
  eos update kvm-disk centos-stream9-3 --disk-size +50G

  # Set absolute disk size
  eos update kvm-disk centos-stream9-3 --disk-size 200G

  # Preview changes without applying
  eos update kvm-disk centos-stream9-3 --disk-size +50G --dry-run

  # Force shrink (DANGEROUS - ensure guest filesystem shrunk first!)
  eos update kvm-disk centos-stream9-3 --disk-size -10G --force

  # Custom backup location
  eos update kvm-disk centos-stream9-3 --disk-size +50G --backup-path /backups/custom.qcow2

GUEST OS OPERATIONS:
If VM is running with guest agent, automatically performs:
  Linux: growpart, pvresize, lvextend, xfs_growfs/resize2fs
  Windows: Not yet implemented (manual steps required)

WITHOUT guest agent, you must manually resize inside guest:
  Ubuntu/Debian:
    growpart /dev/vda 2
    pvresize /dev/vda2
    lvextend -l +100%FREE /dev/mapper/vg-root
    resize2fs /dev/mapper/vg-root

  RHEL/Rocky (XFS):
    growpart /dev/vda 2
    pvresize /dev/vda2
    lvextend -l +100%FREE /dev/mapper/vg-root
    xfs_growfs /`,
	RunE: eos_cli.Wrap(runUpdateKVMDisk),
}

func init() {
	UpdateKVMDiskCmd.Flags().StringVar(&diskSize, "disk-size", "", "Disk size change (+50G, -10G, or absolute 200G)")
	UpdateKVMDiskCmd.Flags().BoolVar(&diskForce, "force", false, "Skip safety checks (dangerous!)")
	UpdateKVMDiskCmd.Flags().BoolVar(&diskDryRun, "dry-run", false, "Preview changes without applying")
	UpdateKVMDiskCmd.Flags().BoolVar(&diskSkipBackup, "skip-backup", false, "Skip backup creation (not recommended)")
	UpdateKVMDiskCmd.Flags().BoolVar(&diskSkipVerify, "skip-verify", false, "Skip verification after resize")
	UpdateKVMDiskCmd.Flags().StringVar(&diskBackupPath, "backup-path", "", "Custom backup file path")

	_ = UpdateKVMDiskCmd.MarkFlagRequired("disk-size")

	UpdateCmd.AddCommand(UpdateKVMDiskCmd)
}

func runUpdateKVMDisk(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) (err error) {
	logger := otelzap.Ctx(rc.Ctx)
	defer rc.End(&err)

	// Get VM name from args
	if len(args) == 0 {
		return fmt.Errorf("VM name required as argument")
	}
	vmName := args[0]

	logger.Info("Starting disk resize operation",
		zap.String("vm", vmName),
		zap.String("size", diskSize))

	// Parse size specification
	change, err := disk.ParseSizeChange(diskSize)
	if err != nil {
		return fmt.Errorf("invalid size specification: %w", err)
	}

	// Phase 1: ASSESS
	logger.Info("Phase 1: ASSESS - Analyzing VM configuration")
	assessment, err := disk.Assess(rc.Ctx, vmName, change)
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// Display assessment results
	disk.DisplayAssessment(rc.Ctx, assessment)

	// Safety check
	if !assessment.SafeToResize && !diskForce {
		logger.Error("Resize blocked due to safety concerns",
			zap.Int("high_risks", disk.CountHighRisks(assessment.Risks)))

		for _, risk := range assessment.Risks {
			if risk.Level == disk.RiskLevelHigh {
				logger.Error("HIGH RISK",
					zap.String("description", risk.Description),
					zap.String("mitigation", risk.Mitigation))
			}
		}

		return fmt.Errorf("resize unsafe - use --force to override (not recommended)")
	}

	if diskForce && !assessment.SafeToResize {
		logger.Warn("Safety checks bypassed with --force flag")
	}

	// Dry run mode
	if diskDryRun {
		logger.Info("DRY RUN MODE - No changes will be made")
		disk.DisplayPlan(rc.Ctx, assessment)
		return nil
	}

	// Confirm with user
	if !diskForce {
		if !disk.ConfirmResize(assessment) {
			logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Phase 2 & 3: INTERVENE and EVALUATE (handled by manager)
	manager := disk.NewManager()

	req := &disk.ResizeRequest{
		VMName:     vmName,
		SizeSpec:   diskSize,
		Force:      diskForce,
		DryRun:     false,
		SkipBackup: diskSkipBackup,
		SkipVerify: diskSkipVerify,
		BackupPath: diskBackupPath,
	}

	if err := manager.Resize(rc.Ctx, req); err != nil {
		logger.Error("Resize failed", zap.Error(err))

		// Attempt rollback
		logger.Warn("Attempting automatic rollback...")
		if rbErr := manager.Rollback(rc.Ctx, vmName); rbErr != nil {
			logger.Error("Rollback also failed",
				zap.Error(rbErr),
				zap.String("original_error", err.Error()))
			return fmt.Errorf("resize failed and rollback failed: %w (rollback error: %v)", err, rbErr)
		}

		logger.Info("Successfully rolled back changes")
		return fmt.Errorf("resize failed (successfully rolled back): %w", err)
	}

	logger.Info("Disk resize completed successfully",
		zap.String("vm", vmName),
		zap.String("new_size", disk.FormatBytes(assessment.RequestedSizeBytes)))

	// Provide post-resize instructions if needed
	if assessment.State == "shut off" || !assessment.HasGuestAgent {
		disk.DisplayPostResizeInstructions(rc.Ctx, assessment)
	}

	return nil
}
