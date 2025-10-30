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
	resizeFilesystem         bool
	lvPath                   string
	devicePath               string
	mountpoint               string
	fsType                   string
	expandTarget             string
	expandAll                bool
	expandAllowPartitionGrow bool
	expandForceLUKS          bool
	expandDryRun             bool
	expandAssumeYes          bool
	expandSkipAptInstall     bool
	expandLogJSON            bool
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
		if expandTarget == "" && (expandAll || expandAllowPartitionGrow || expandForceLUKS || expandDryRun || expandAssumeYes || expandSkipAptInstall || expandLogJSON) {
			return fmt.Errorf("expansion flags require --expand root")
		}

		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Starting storage update operation")

		if expandTarget != "" {
			if expandTarget != "root" {
				return fmt.Errorf("unsupported expand target: %s", expandTarget)
			}

			opts := storage.RootExpandOptions{
				AllowPartitionGrow: expandAllowPartitionGrow,
				ForceLUKS:          expandForceLUKS,
				DryRun:             expandDryRun,
				AssumeYes:          expandAssumeYes,
				SkipAptInstall:     expandSkipAptInstall,
				LogJSON:            expandLogJSON,
				UseAllFreeSpace:    expandAll,
			}

			return storage.ExpandRoot(rc, opts)
		}

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
	UpdateStorageCmd.Flags().StringVar(&expandTarget, "expand", "", "Expand a storage target (supported: root)")
	UpdateStorageCmd.Flags().BoolVar(&expandAll, "all", false, "Consume all remaining free space during expansion")
	UpdateStorageCmd.Flags().BoolVar(&expandAllowPartitionGrow, "allow-partition-grow", false, "Allow partition growth when expanding")
	UpdateStorageCmd.Flags().BoolVar(&expandForceLUKS, "luks", false, "Force LUKS workflow (error if root PV not backed by LUKS)")
	UpdateStorageCmd.Flags().BoolVar(&expandDryRun, "dry-run", false, "Show planned commands without executing them")
	UpdateStorageCmd.Flags().BoolVar(&expandAssumeYes, "yes", false, "Automatically confirm prompts")
	UpdateStorageCmd.Flags().BoolVar(&expandSkipAptInstall, "skip-apt-install", false, "Do not attempt to install missing dependencies")
	UpdateStorageCmd.Flags().BoolVar(&expandLogJSON, "log-json", false, "Emit JSON summary of expansion results")
}
