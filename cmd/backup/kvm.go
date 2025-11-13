//go:build linux

// cmd/backup/kvm.go

package backup

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// kvmCmd handles KVM snapshot backup operations
var kvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "KVM virtual machine snapshot backup operations",
	Long: `Manage KVM virtual machine snapshots and backups using libvirt.

Features:
  - Create VM snapshots with memory and disk state
  - Export snapshots to backup storage
  - Restore VMs from snapshot backups
  - Verify snapshot integrity
  - List and manage VM snapshots

Examples:
  # Create a live snapshot of a VM
  eos backup kvm create --vm-name myvm --snapshot-name backup-$(date +%Y%m%d) --live

  # Backup a snapshot to storage
  eos backup kvm export --vm-name myvm --snapshot-name mysnap --backup-dir /var/backups/kvm

  # List all snapshots for a VM
  eos backup kvm list --vm-name myvm

  # Restore VM from backup
  eos backup kvm restore --vm-name myvm --backup-path /var/backups/kvm/myvm_backup_20240101

  # Verify snapshot integrity
  eos backup kvm verify --vm-name myvm --snapshot-name mysnap`,
}

// kvmCreateCmd creates VM snapshots
var kvmCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a KVM virtual machine snapshot",
	Long:  `Create a snapshot of a KVM virtual machine including memory and disk state.`,
	RunE:  eos_cli.Wrap(runKVMCreate),
}

// kvmExportCmd exports snapshots to backup storage
var kvmExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export KVM snapshot to backup storage",
	Long:  `Export a KVM snapshot to external backup storage for archival.`,
	RunE:  eos_cli.Wrap(runKVMExport),
}

// kvmListCmd lists VM snapshots
var kvmListCmd = &cobra.Command{
	Use:   "list",
	Short: "List KVM virtual machine snapshots",
	Long:  `List all snapshots for a specified virtual machine.`,
	RunE:  eos_cli.Wrap(runKVMList),
}

// kvmRestoreCmd restores VMs from backups
var kvmRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore KVM virtual machine from backup",
	Long:  `Restore a KVM virtual machine from a previously created snapshot backup.`,
	RunE:  eos_cli.Wrap(runKVMRestore),
}

// kvmVerifyCmd verifies snapshot integrity
var kvmVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify KVM snapshot integrity",
	Long:  `Verify the integrity and accessibility of a KVM snapshot.`,
	RunE:  eos_cli.Wrap(runKVMVerify),
}

// kvmDeleteCmd deletes VM snapshots
var kvmDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete KVM virtual machine snapshot",
	Long:  `Delete a KVM snapshot and optionally its metadata.`,
	RunE:  eos_cli.Wrap(runKVMDelete),
}

func init() {
	// Add KVM subcommands
	kvmCmd.AddCommand(kvmCreateCmd)
	kvmCmd.AddCommand(kvmExportCmd)
	kvmCmd.AddCommand(kvmListCmd)
	kvmCmd.AddCommand(kvmRestoreCmd)
	kvmCmd.AddCommand(kvmVerifyCmd)
	kvmCmd.AddCommand(kvmDeleteCmd)

	// Add KVM command to backup
	BackupCmd.AddCommand(kvmCmd)

	// Create command flags
	kvmCreateCmd.Flags().String("vm-name", "", "Name of the virtual machine (required)")
	kvmCreateCmd.Flags().String("snapshot-name", "", "Name for the snapshot (prompted if not provided)")
	kvmCreateCmd.Flags().String("description", "", "Description for the snapshot")
	kvmCreateCmd.Flags().Bool("include-memory", true, "Include memory state in snapshot")
	kvmCreateCmd.Flags().Bool("include-disk", true, "Include disk state in snapshot")
	kvmCreateCmd.Flags().Bool("live", false, "Create live snapshot (VM keeps running)")
	kvmCreateCmd.Flags().String("compression", "none", "Compression type (none, gzip, xz)")
	kvmCreateCmd.Flags().Duration("timeout", 10*time.Minute, "Snapshot creation timeout")

	// Export command flags
	kvmExportCmd.Flags().String("vm-name", "", "Name of the virtual machine (required)")
	kvmExportCmd.Flags().String("snapshot-name", "", "Name of the snapshot to export (prompted if not provided)")
	kvmExportCmd.Flags().String("backup-dir", "/var/backups/kvm", "Backup directory path")
	kvmExportCmd.Flags().String("compression", "gzip", "Compression type (none, gzip, xz)")

	// List command flags
	kvmListCmd.Flags().String("vm-name", "", "Name of the virtual machine (required)")
	kvmListCmd.Flags().Bool("detailed", false, "Show detailed snapshot information")

	// Restore command flags
	kvmRestoreCmd.Flags().String("vm-name", "", "Name of the virtual machine (required)")
	kvmRestoreCmd.Flags().String("backup-path", "", "Path to backup directory (prompted if not provided)")

	// Verify command flags
	kvmVerifyCmd.Flags().String("vm-name", "", "Name of the virtual machine (required)")
	kvmVerifyCmd.Flags().String("snapshot-name", "", "Name of the snapshot to verify (prompted if not provided)")

	// Delete command flags
	kvmDeleteCmd.Flags().String("vm-name", "", "Name of the virtual machine (required)")
	kvmDeleteCmd.Flags().String("snapshot-name", "", "Name of the snapshot to delete (prompted if not provided)")
	kvmDeleteCmd.Flags().Bool("delete-metadata", false, "Also delete snapshot metadata")
	kvmDeleteCmd.Flags().Bool("force", false, "Force deletion without confirmation")
}

func runKVMCreate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get VM name (required)
	vmName, _ := cmd.Flags().GetString("vm-name")
	if vmName == "" {
		logger.Info("terminal prompt: Please enter VM name")
		var err error
		vmName, err = eos_io.PromptInput(rc, "VM name: ", "vm_name")
		if err != nil {
			return fmt.Errorf("failed to read VM name: %w", err)
		}
	}

	// Get snapshot name
	snapshotName, _ := cmd.Flags().GetString("snapshot-name")
	if snapshotName == "" {
		logger.Info("terminal prompt: Please enter snapshot name")
		defaultName := fmt.Sprintf("snapshot-%s", time.Now().Format("20060102-150405"))
		var err error
		snapshotName, err = eos_io.PromptInput(rc, fmt.Sprintf("Snapshot name [%s]: ", defaultName), "snapshot_name")
		if err != nil {
			return fmt.Errorf("failed to read snapshot name: %w", err)
		}
		if snapshotName == "" {
			snapshotName = defaultName
		}
	}

	// Get other flags
	description, _ := cmd.Flags().GetString("description")
	includeMemory, _ := cmd.Flags().GetBool("include-memory")
	includeDisk, _ := cmd.Flags().GetBool("include-disk")
	liveSnapshot, _ := cmd.Flags().GetBool("live")
	compression, _ := cmd.Flags().GetString("compression")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	// Create snapshot configuration
	config := &kvm.SnapshotConfig{
		VMName:        vmName,
		SnapshotName:  snapshotName,
		Description:   description,
		IncludeMemory: includeMemory,
		IncludeDisk:   includeDisk,
		Compression:   compression,
		LiveSnapshot:  liveSnapshot,
		Timeout:       timeout,
	}

	// Create snapshot manager
	manager := kvm.NewSnapshotManager(config, otelzap.Ctx(rc.Ctx))

	// Create snapshot
	result, err := manager.CreateSnapshot(rc)
	if err != nil {
		return fmt.Errorf("snapshot creation failed: %w", err)
	}

	logger.Info("KVM snapshot created successfully",
		zap.String("vm_name", vmName),
		zap.String("snapshot_name", snapshotName),
		zap.Duration("duration", result.Duration))

	return nil
}

func runKVMExport(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get VM name (required)
	vmName, _ := cmd.Flags().GetString("vm-name")
	if vmName == "" {
		logger.Info("terminal prompt: Please enter VM name")
		var err error
		vmName, err = eos_io.PromptInput(rc, "VM name: ", "vm_name")
		if err != nil {
			return fmt.Errorf("failed to read VM name: %w", err)
		}
	}

	// Get snapshot name
	snapshotName, _ := cmd.Flags().GetString("snapshot-name")
	if snapshotName == "" {
		logger.Info("terminal prompt: Please enter snapshot name")
		var err error
		snapshotName, err = eos_io.PromptInput(rc, "Snapshot name: ", "snapshot_name")
		if err != nil {
			return fmt.Errorf("failed to read snapshot name: %w", err)
		}
	}

	// Get other flags
	backupDir, _ := cmd.Flags().GetString("backup-dir")
	compression, _ := cmd.Flags().GetString("compression")

	// Create snapshot configuration
	config := &kvm.SnapshotConfig{
		VMName:      vmName,
		BackupDir:   backupDir,
		Compression: compression,
	}

	// Create snapshot manager
	manager := kvm.NewSnapshotManager(config, otelzap.Ctx(rc.Ctx))

	// Export snapshot
	result, err := manager.BackupSnapshot(rc, snapshotName)
	if err != nil {
		return fmt.Errorf("snapshot export failed: %w", err)
	}

	logger.Info("KVM snapshot exported successfully",
		zap.String("vm_name", vmName),
		zap.String("snapshot_name", snapshotName),
		zap.String("backup_path", result.BackupPath),
		zap.Int64("backup_size", result.BackupSize))

	return nil
}

func runKVMList(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get VM name (required)
	vmName, _ := cmd.Flags().GetString("vm-name")
	if vmName == "" {
		logger.Info("terminal prompt: Please enter VM name")
		var err error
		vmName, err = eos_io.PromptInput(rc, "VM name: ", "vm_name")
		if err != nil {
			return fmt.Errorf("failed to read VM name: %w", err)
		}
	}

	detailed, _ := cmd.Flags().GetBool("detailed")

	// Create snapshot configuration
	config := &kvm.SnapshotConfig{
		VMName: vmName,
	}

	// Create snapshot manager
	manager := kvm.NewSnapshotManager(config, otelzap.Ctx(rc.Ctx))

	// List snapshots
	snapshots, err := manager.ListSnapshots(rc)
	if err != nil {
		return fmt.Errorf("failed to list snapshots: %w", err)
	}

	logger.Info("Found KVM snapshots",
		zap.String("vm_name", vmName),
		zap.Int("count", len(snapshots)))

	// Display snapshots in a user-friendly format
	if len(snapshots) == 0 {
		logger.Info("No snapshots found for VM", zap.String("vm_name", vmName))
		return nil
	}

	for _, snapshot := range snapshots {
		if detailed {
			logger.Info("Snapshot details",
				zap.String("name", snapshot.Name),
				zap.String("state", snapshot.State),
				zap.Time("created", snapshot.CreationTime),
				zap.String("description", snapshot.Description),
				zap.String("disk_path", snapshot.DiskPath),
				zap.String("memory_path", snapshot.MemoryPath),
				zap.Int64("size", snapshot.Size))
		} else {
			logger.Info("Snapshot",
				zap.String("name", snapshot.Name),
				zap.String("state", snapshot.State),
				zap.Time("created", snapshot.CreationTime))
		}
	}

	return nil
}

func runKVMRestore(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get VM name (required)
	vmName, _ := cmd.Flags().GetString("vm-name")
	if vmName == "" {
		logger.Info("terminal prompt: Please enter VM name")
		var err error
		vmName, err = eos_io.PromptInput(rc, "VM name: ", "vm_name")
		if err != nil {
			return fmt.Errorf("failed to read VM name: %w", err)
		}
	}

	// Get backup path
	backupPath, _ := cmd.Flags().GetString("backup-path")
	if backupPath == "" {
		logger.Info("terminal prompt: Please enter backup path")
		var err error
		backupPath, err = eos_io.PromptInput(rc, "Backup path: ", "backup_path")
		if err != nil {
			return fmt.Errorf("failed to read backup path: %w", err)
		}
	}

	// Create snapshot configuration
	config := &kvm.SnapshotConfig{
		VMName: vmName,
	}

	// Create snapshot manager
	manager := kvm.NewSnapshotManager(config, otelzap.Ctx(rc.Ctx))

	// Restore snapshot
	err := manager.RestoreSnapshot(rc, backupPath)
	if err != nil {
		return fmt.Errorf("snapshot restore failed: %w", err)
	}

	logger.Info("KVM snapshot restored successfully",
		zap.String("vm_name", vmName),
		zap.String("backup_path", backupPath))

	return nil
}

func runKVMVerify(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get VM name (required)
	vmName, _ := cmd.Flags().GetString("vm-name")
	if vmName == "" {
		logger.Info("terminal prompt: Please enter VM name")
		var err error
		vmName, err = eos_io.PromptInput(rc, "VM name: ", "vm_name")
		if err != nil {
			return fmt.Errorf("failed to read VM name: %w", err)
		}
	}

	// Get snapshot name
	snapshotName, _ := cmd.Flags().GetString("snapshot-name")
	if snapshotName == "" {
		logger.Info("terminal prompt: Please enter snapshot name")
		var err error
		snapshotName, err = eos_io.PromptInput(rc, "Snapshot name: ", "snapshot_name")
		if err != nil {
			return fmt.Errorf("failed to read snapshot name: %w", err)
		}
	}

	// Create snapshot configuration
	config := &kvm.SnapshotConfig{
		VMName: vmName,
	}

	// Create snapshot manager
	manager := kvm.NewSnapshotManager(config, otelzap.Ctx(rc.Ctx))

	// Verify snapshot
	err := manager.VerifySnapshot(rc, snapshotName)
	if err != nil {
		return fmt.Errorf("snapshot verification failed: %w", err)
	}

	logger.Info("KVM snapshot verified successfully",
		zap.String("vm_name", vmName),
		zap.String("snapshot_name", snapshotName))

	return nil
}

func runKVMDelete(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get VM name (required)
	vmName, _ := cmd.Flags().GetString("vm-name")
	if vmName == "" {
		logger.Info("terminal prompt: Please enter VM name")
		var err error
		vmName, err = eos_io.PromptInput(rc, "VM name: ", "vm_name")
		if err != nil {
			return fmt.Errorf("failed to read VM name: %w", err)
		}
	}

	// Get snapshot name
	snapshotName, _ := cmd.Flags().GetString("snapshot-name")
	if snapshotName == "" {
		logger.Info("terminal prompt: Please enter snapshot name")
		var err error
		snapshotName, err = eos_io.PromptInput(rc, "Snapshot name: ", "snapshot_name")
		if err != nil {
			return fmt.Errorf("failed to read snapshot name: %w", err)
		}
	}

	deleteMetadata, _ := cmd.Flags().GetBool("delete-metadata")
	force, _ := cmd.Flags().GetBool("force")

	// Confirm deletion unless force flag is used
	if !force {
		logger.Info("terminal prompt: Confirm snapshot deletion")
		confirmation, err := eos_io.PromptInput(rc, fmt.Sprintf("Delete snapshot '%s' for VM '%s'? (y/N): ", snapshotName, vmName), "confirmation")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if confirmation != "y" && confirmation != "Y" && confirmation != "yes" {
			logger.Info("Snapshot deletion cancelled")
			return nil
		}
	}

	// Create snapshot configuration
	config := &kvm.SnapshotConfig{
		VMName: vmName,
	}

	// Create snapshot manager
	manager := kvm.NewSnapshotManager(config, otelzap.Ctx(rc.Ctx))

	// Delete snapshot
	err := manager.DeleteSnapshot(rc, snapshotName, deleteMetadata)
	if err != nil {
		return fmt.Errorf("snapshot deletion failed: %w", err)
	}

	logger.Info("KVM snapshot deleted successfully",
		zap.String("vm_name", vmName),
		zap.String("snapshot_name", snapshotName),
		zap.Bool("metadata_deleted", deleteMetadata))

	return nil
}
