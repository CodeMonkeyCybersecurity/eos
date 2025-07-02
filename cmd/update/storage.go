// cmd/update/storage.go
package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	resizeFilesystem bool
	lvPath          string
	devicePath      string
	mountpoint      string
	fsType          string
)

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

func runUpdateStorage(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	if resizeFilesystem {
		logger.Info("Starting automatic Ubuntu LVM resize")
		return storage.AutoResizeUbuntuLVM(rc)
	}
	
	if lvPath != "" {
		logger.Info("Extending logical volume", zap.String("lv_path", lvPath))
		if err := storage.ExtendLogicalVolume(rc, lvPath); err != nil {
			return err
		}
		
		// If device path is provided, resize the filesystem too
		if devicePath != "" {
			logger.Info("Resizing filesystem", zap.String("device_path", devicePath))
			if fsType == "xfs" && mountpoint != "" {
				return storage.ResizeXfsFilesystem(rc, mountpoint)
			} else {
				return storage.ResizeExt4Filesystem(rc, devicePath)
			}
		}
		return nil
	}
	
	if devicePath != "" {
		logger.Info("Resizing filesystem", zap.String("device_path", devicePath))
		if fsType == "xfs" && mountpoint != "" {
			return storage.ResizeXfsFilesystem(rc, mountpoint)
		} else {
			return storage.ResizeExt4Filesystem(rc, devicePath)
		}
	}
	
	// Default: show help
	logger.Info("No specific action specified, showing help")
	return cmd.Help()
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
