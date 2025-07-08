// cmd/update/storage.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Global flags
var (
	resizeFilesystem bool
	lvPath          string
	devicePath      string
	mountpoint      string
	fsType          string
)

// runUpdateStorage handles the storage update operation
func runUpdateStorage(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting storage update operation")
	
	if resizeFilesystem {
		logger.Info("Auto-resizing Ubuntu LVM")
		if err := storage.AutoResizeUbuntuLVM(rc); err != nil {
			return fmt.Errorf("failed to auto-resize LVM: %w", err)
		}
		logger.Info("LVM auto-resize completed successfully")
		return nil
	}
	
	if lvPath != "" {
		logger.Info("Extending logical volume", zap.String("lv_path", lvPath))
		if err := storage.ExtendLogicalVolume(rc, lvPath); err != nil {
			return fmt.Errorf("failed to extend logical volume: %w", err)
		}
		logger.Info("Logical volume extended successfully")
	}
	
	if devicePath != "" {
		logger.Info("Resizing filesystem", 
			zap.String("device", devicePath),
			zap.String("fs_type", fsType))
		if err := storage.ResizeFilesystem(rc, devicePath, fsType, mountpoint); err != nil {
			return fmt.Errorf("failed to resize filesystem: %w", err)
		}
		logger.Info("Filesystem resized successfully")
	}
	
	if lvPath == "" && devicePath == "" && !resizeFilesystem {
		logger.Info("No storage operations specified")
		return fmt.Errorf("no storage operation specified. Use --resize, --lv-path, or --device")
	}
	
	return nil
}


// updateStorageCmd handles updating storage information
var UpdateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Update and resize storage resources",
	Long: `Update storage configurations including:
- Resizing LVM logical volumes
- Extending filesystems
- Managing fstab entries

Examples:
  eos update storage --resize                    # Auto-resize Ubuntu LVM
  eos update storage --lv-path /dev/vg/lv       # Extend specific LV
  eos update storage --device /dev/mapper/lv    # Resize specific filesystem`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runUpdateStorage(rc, cmd, args)
	}),
}

var UpdateStorageFstabCmd = &cobra.Command{
	Use:   "fstab",
	Short: "Update fstab entries interactively",
	Long: `Interactive fstab management including:
- Listing available block devices
- Adding new mount points
- Backing up current fstab
- Mounting new filesystems`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return storage.InteractiveFstabManager(rc)
	}),
}

// init registers subcommands for the update command
func init() {
	UpdateCmd.AddCommand(UpdateStorageCmd)
	UpdateStorageCmd.AddCommand(UpdateStorageFstabCmd)

	UpdateStorageCmd.Flags().BoolVar(&resizeFilesystem, "resize", false, "Auto-resize Ubuntu LVM (extends LV and filesystem)")
	UpdateStorageCmd.Flags().StringVar(&lvPath, "lv-path", "", "Logical volume path to extend (e.g., /dev/ubuntu-vg/ubuntu-lv)")
	UpdateStorageCmd.Flags().StringVar(&devicePath, "device", "", "Device path for filesystem resize (e.g., /dev/mapper/ubuntu--vg-ubuntu--lv)")
	UpdateStorageCmd.Flags().StringVar(&mountpoint, "mountpoint", "", "Mountpoint for XFS filesystem resize")
	UpdateStorageCmd.Flags().StringVar(&fsType, "fs-type", "ext4", "Filesystem type (ext4 or xfs)")
}
