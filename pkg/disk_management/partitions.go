// pkg/disk_management/partitions.go
package disk_management

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreatePartition creates a new partition on the specified disk following Assess → Intervene → Evaluate pattern
func CreatePartition(rc *eos_io.RuntimeContext, device string, options *PartitionOptions) (*PartitionOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	// Check for nil options first to avoid nil pointer dereference
	if options == nil {
		options = DefaultPartitionOptions()
	}

	// ASSESS
	logger.Info("Assessing partition creation requirements",
		zap.String("device", device),
		zap.String("type", options.PartitionType),
		zap.Bool("dry_run", options.DryRun))

	operation := &PartitionOperation{
		Operation: "create",
		Device:    device,
		Timestamp: time.Now(),
		DryRun:    options.DryRun,
	}

	// Check privileges
	privilegeManager := privilege_check.NewPrivilegeManager(nil)
	if err := privilegeManager.CheckSudoOnly(rc); err != nil {
		operation.Success = false
		operation.Message = "Root privileges required for partition operations"
		logger.Error("Insufficient privileges", zap.Error(err))
		return operation, err
	}

	// Safety checks
	if err := performSafetyChecks(device); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Safety check failed: %v", err)
		logger.Error("Safety check failed", zap.Error(err))
		return operation, err
	}

	// INTERVENE
	if options.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would create partition on %s", device)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would create partition")
		return operation, nil
	}

	logger.Info("Creating partition", zap.String("device", device))

	// Backup partition table if enabled
	if err := backupPartitionTable(rc, device); err != nil {
		logger.Warn("Failed to backup partition table", zap.Error(err))
		// Don't fail the operation for backup errors
	}

	// Create partition using fdisk
	if err := createPartitionWithFdisk(rc, device, options); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to create partition: %v", err)
		logger.Error("Partition creation failed", zap.Error(err))
		return operation, err
	}

	// EVALUATE
	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully created partition on %s", device)
	operation.Duration = time.Since(startTime)

	logger.Info("Partition created successfully",
		zap.String("device", device),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// FormatPartition formats a partition with the specified filesystem following Assess → Intervene → Evaluate pattern
func FormatPartition(rc *eos_io.RuntimeContext, device string, filesystem string, label string, dryRun bool) (*FormatOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	// ASSESS
	logger.Info("Assessing partition format requirements",
		zap.String("device", device),
		zap.String("filesystem", filesystem),
		zap.String("label", label),
		zap.Bool("dry_run", dryRun))

	operation := &FormatOperation{
		Device:     device,
		FileSystem: filesystem,
		Label:      label,
		Timestamp:  time.Now(),
		DryRun:     dryRun,
	}

	// Check privileges
	privilegeManager := privilege_check.NewPrivilegeManager(nil)
	if err := privilegeManager.CheckSudoOnly(rc); err != nil {
		operation.Success = false
		operation.Message = "Root privileges required for format operations"
		logger.Error("Insufficient privileges", zap.Error(err))
		return operation, err
	}

	// INTERVENE
	if dryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would format %s as %s", device, filesystem)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would format partition")
		return operation, nil
	}

	logger.Info("Formatting partition",
		zap.String("device", device),
		zap.String("filesystem", filesystem))

	// Format the partition
	var cmd *exec.Cmd
	switch filesystem {
	case "ext4":
		args := []string{"-F", device}
		if label != "" {
			args = append([]string{"-L", label}, args...)
		}
		cmd = exec.CommandContext(rc.Ctx, "mkfs.ext4", args...)
	case "ext3":
		args := []string{"-F", device}
		if label != "" {
			args = append([]string{"-L", label}, args...)
		}
		cmd = exec.CommandContext(rc.Ctx, "mkfs.ext3", args...)
	case "xfs":
		args := []string{"-f", device}
		if label != "" {
			args = append([]string{"-L", label}, args...)
		}
		cmd = exec.CommandContext(rc.Ctx, "mkfs.xfs", args...)
	case "btrfs":
		args := []string{"-f", device}
		if label != "" {
			args = append([]string{"-L", label}, args...)
		}
		cmd = exec.CommandContext(rc.Ctx, "mkfs.btrfs", args...)
	default:
		operation.Success = false
		operation.Message = fmt.Sprintf("Unsupported filesystem: %s", filesystem)
		logger.Error("Unsupported filesystem", zap.String("filesystem", filesystem))
		return operation, fmt.Errorf("unsupported filesystem: %s", filesystem)
	}

	output, err := cmd.CombinedOutput()
	operation.Output = string(output)
	operation.Duration = time.Since(startTime)

	// EVALUATE
	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Format failed: %v", err)
		logger.Error("Format operation failed", zap.Error(err), zap.String("output", operation.Output))
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully formatted %s as %s", device, filesystem)

	logger.Info("Partition formatted successfully",
		zap.String("device", device),
		zap.String("filesystem", filesystem),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// MountPartition mounts a partition to the specified mount point following Assess → Intervene → Evaluate pattern
func MountPartition(rc *eos_io.RuntimeContext, device string, mountPoint string, options string, dryRun bool) (*MountOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	// ASSESS
	logger.Info("Assessing mount requirements",
		zap.String("device", device),
		zap.String("mount_point", mountPoint),
		zap.String("options", options),
		zap.Bool("dry_run", dryRun))

	operation := &MountOperation{
		Operation:  "mount",
		Device:     device,
		MountPoint: mountPoint,
		Timestamp:  time.Now(),
		DryRun:     dryRun,
	}

	// Check privileges
	privilegeManager := privilege_check.NewPrivilegeManager(nil)
	if err := privilegeManager.CheckSudoOnly(rc); err != nil {
		operation.Success = false
		operation.Message = "Root privileges required for mount operations"
		logger.Error("Insufficient privileges", zap.Error(err))
		return operation, err
	}

	// INTERVENE
	if dryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would mount %s at %s", device, mountPoint)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would mount partition")
		return operation, nil
	}

	logger.Info("Mounting partition",
		zap.String("device", device),
		zap.String("mount_point", mountPoint))

	// Create mount point if it doesn't exist
	if err := os.MkdirAll(mountPoint, shared.ServiceDirPerm); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to create mount point: %v", err)
		logger.Error("Failed to create mount point", zap.Error(err))
		return operation, err
	}

	// Build mount command
	args := []string{device, mountPoint}
	if options != "" {
		args = append([]string{"-o", options}, args...)
	}

	cmd := exec.CommandContext(rc.Ctx, "mount", args...)
	output, err := cmd.CombinedOutput()
	operation.Duration = time.Since(startTime)

	// EVALUATE
	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Mount failed: %v", err)
		logger.Error("Mount operation failed", zap.Error(err), zap.String("output", string(output)))
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully mounted %s at %s", device, mountPoint)

	logger.Info("Partition mounted successfully",
		zap.String("device", device),
		zap.String("mount_point", mountPoint),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// Helper functions

func performSafetyChecks(device string) error {
	// Check if device exists
	if _, err := os.Stat(device); err != nil {
		return fmt.Errorf("device %s does not exist", device)
	}

	// TODO: Add more safety checks like checking if device is mounted
	return nil
}

func createPartitionWithFdisk(rc *eos_io.RuntimeContext, device string, options *PartitionOptions) error {
	// This is a simplified implementation - production would need more sophisticated fdisk interaction
	fdiskCommands := "n\np\n1\n\n\nw\n"

	cmd := exec.CommandContext(rc.Ctx, "fdisk", device)
	cmd.Stdin = strings.NewReader(fdiskCommands)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fdisk failed: %w, output: %s", err, string(output))
	}

	return nil
}

func backupPartitionTable(rc *eos_io.RuntimeContext, device string) error {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupFile := fmt.Sprintf("/tmp/partition_table_%s_%s.backup",
		strings.ReplaceAll(device, "/", "_"), timestamp)

	cmd := exec.CommandContext(rc.Ctx, "sfdisk", "-d", device)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to dump partition table: %w", err)
	}

	return os.WriteFile(backupFile, output, shared.ConfigFilePerm)
}
