package update

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

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
	displayAssessment(logger, assessment)

	// Safety check
	if !assessment.SafeToResize && !diskForce {
		logger.Error("Resize blocked due to safety concerns",
			zap.Int("high_risks", countHighRisks(assessment.Risks)))

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
		displayPlan(logger, assessment)
		return nil
	}

	// Confirm with user
	if !diskForce {
		if !confirmResize(assessment) {
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
		displayPostResizeInstructions(logger, assessment)
	}

	return nil
}

func displayAssessment(logger *otelzap.LoggerWithCtx, a *disk.Assessment) {
	logger.Info("╔═══════════════════════════════════════════════════════════════╗")
	logger.Info("║                    ASSESSMENT RESULTS                         ║")
	logger.Info("╠═══════════════════════════════════════════════════════════════╣")
	logger.Info(fmt.Sprintf("║ VM Name: %-52s║", a.VMName))
	logger.Info(fmt.Sprintf("║ State: %-54s║", a.State))
	logger.Info(fmt.Sprintf("║ Current Size: %-47s║", disk.FormatBytes(a.CurrentSizeBytes)))
	logger.Info(fmt.Sprintf("║ Requested Size: %-45s║", disk.FormatBytes(a.RequestedSizeBytes)))
	logger.Info(fmt.Sprintf("║ Change: %-53s║", disk.FormatBytes(a.ChangeBytes)))
	logger.Info(fmt.Sprintf("║ Disk Format: %-48s║", a.Format))
	logger.Info(fmt.Sprintf("║ Guest Agent: %-48s║", formatBool(a.HasGuestAgent)))
	logger.Info(fmt.Sprintf("║ Backup Available: %-43s║", formatBool(a.BackupExists)))
	if a.BackupExists {
		logger.Info(fmt.Sprintf("║ Backup Age: %-49s║", a.BackupAge.Round(time.Minute).String()))
	}
	logger.Info(fmt.Sprintf("║ Host Free Space: %-44s║", disk.FormatBytes(a.HostFreeSpaceBytes)))
	logger.Info("╚═══════════════════════════════════════════════════════════════╝")

	// Display risks
	if len(a.Risks) > 0 {
		logger.Info("Identified Risks:")
		for _, risk := range a.Risks {
			level := strings.ToUpper(string(risk.Level))
			logger.Info(fmt.Sprintf("  [%s] %s", level, risk.Description))
			logger.Info(fmt.Sprintf("         Mitigation: %s", risk.Mitigation))
		}
	}

	// Display required actions
	if len(a.RequiredActions) > 0 {
		logger.Info("Required Actions:")
		for _, action := range a.RequiredActions {
			logger.Info(fmt.Sprintf("  • %s", action))
		}
	}
}

func displayPlan(logger *otelzap.LoggerWithCtx, a *disk.Assessment) {
	logger.Info("Planned Operations:")
	logger.Info("  1. Create safety backup")
	logger.Info(fmt.Sprintf("  2. Resize disk from %s to %s",
		disk.FormatBytes(a.CurrentSizeBytes),
		disk.FormatBytes(a.RequestedSizeBytes)))

	if a.State == "running" && a.HasGuestAgent {
		logger.Info("  3. Resize guest filesystem automatically")
	} else {
		logger.Info("  3. Manual guest filesystem resize required")
	}

	logger.Info("  4. Verify resize success")
}

func displayPostResizeInstructions(logger *otelzap.LoggerWithCtx, a *disk.Assessment) {
	logger.Info("")
	logger.Info("POST-RESIZE INSTRUCTIONS:")
	logger.Info("The disk has been resized at the hypervisor level.")

	if a.State == "shut off" {
		logger.Info("Start the VM and perform filesystem resize inside the guest OS:")
	} else {
		logger.Info("Perform filesystem resize inside the guest OS:")
	}

	logger.Info("")
	logger.Info("For Linux guests:")
	logger.Info("  1. growpart /dev/vda 2")
	logger.Info("  2. pvresize /dev/vda2")
	logger.Info("  3. lvextend -l +100%FREE /dev/mapper/vg-root")
	logger.Info("  4. xfs_growfs / (XFS) or resize2fs /dev/mapper/vg-root (ext4)")
	logger.Info("")
	logger.Info("Verify with: df -h")
}

func confirmResize(a *disk.Assessment) bool {
	fmt.Println("")
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    CONFIRMATION REQUIRED                       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("You are about to resize disk for VM '%s'\n", a.VMName)
	fmt.Printf("  From: %s\n", disk.FormatBytes(a.CurrentSizeBytes))
	fmt.Printf("  To:   %s\n", disk.FormatBytes(a.RequestedSizeBytes))
	fmt.Println("")

	if a.ChangeBytes < 0 {
		fmt.Println("⚠️  WARNING: This is a SHRINK operation which can cause DATA LOSS!")
		fmt.Println("Make sure the guest filesystem has been shrunk first!")
		fmt.Println("")
	}

	fmt.Print("Do you want to proceed? (type 'yes' to continue): ")
	var response string
	fmt.Scanln(&response)

	return strings.ToLower(response) == "yes"
}

func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func countHighRisks(risks []disk.Risk) int {
	count := 0
	for _, r := range risks {
		if r.Level == disk.RiskLevelHigh {
			count++
		}
	}
	return count
}
