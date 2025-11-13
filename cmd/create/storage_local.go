package create

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/local"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var StorageLocalCmd = &cobra.Command{
	Use:   "storage-local [volume-name] [device]",
	Short: "Create local storage volume without LVM",
	Long: `Create and manage local storage volumes using modern Linux filesystem tools.
This command formats devices directly with ext4/xfs/btrfs without requiring LVM.

Examples:
  eos create storage-local data-vol /dev/sdb --filesystem ext4 --mount /data
  eos create storage-local logs-vol /dev/sdc --filesystem xfs --mount /var/log/app`,
	Args: cobra.ExactArgs(2),
	RunE: eos_cli.Wrap(runCreateStorageLocal),
}

var (
	localFilesystem string
	localMountPoint string
	localOptions    []string
	forceFormat     bool
)

func init() {
	StorageLocalCmd.Flags().StringVar(&localFilesystem, "filesystem", "ext4", "Filesystem type (ext4, xfs, btrfs)")
	StorageLocalCmd.Flags().StringVar(&localMountPoint, "mount", "", "Mount point (required)")
	StorageLocalCmd.Flags().StringSliceVar(&localOptions, "options", []string{}, "Mount options")
	StorageLocalCmd.Flags().BoolVar(&forceFormat, "force", false, "Force format even if device has data")

	_ = StorageLocalCmd.MarkFlagRequired("mount")
}

func runCreateStorageLocal(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	volumeName := args[0]
	device := args[1]

	logger := otelzap.Ctx(rc.Ctx)

	// CRITICAL: Detect flag-like args (P0-1 fix)
	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}

	logger.Info("Creating local storage volume",
		zap.String("name", volumeName),
		zap.String("device", device),
		zap.String("filesystem", localFilesystem),
		zap.String("mount_point", localMountPoint))

	// Validate inputs
	if !strings.HasPrefix(device, "/dev/") {
		return fmt.Errorf("device must be a full path starting with /dev/")
	}

	supportedFS := map[string]bool{
		"ext4":  true,
		"xfs":   true,
		"btrfs": true,
	}

	if !supportedFS[localFilesystem] {
		return fmt.Errorf("unsupported filesystem: %s (supported: ext4, xfs, btrfs)", localFilesystem)
	}

	// Initialize local storage manager
	manager := local.NewLocalStorageManager(rc)

	// Create volume specification
	spec := &local.VolumeSpec{
		Name:       volumeName,
		Device:     device,
		Filesystem: localFilesystem,
		MountPoint: localMountPoint,
		Options:    localOptions,
	}

	// Create the volume
	diskInfo, err := manager.CreateVolume(rc.Ctx, spec)
	if err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	// Display results
	fmt.Printf(" Local storage volume created successfully:\n")
	fmt.Printf("   Name: %s\n", volumeName)
	fmt.Printf("   Device: %s\n", diskInfo.Device)
	fmt.Printf("   UUID: %s\n", diskInfo.UUID)
	fmt.Printf("   Filesystem: %s\n", diskInfo.Filesystem)
	fmt.Printf("   Mount Point: %s\n", diskInfo.MountPoint)
	fmt.Printf("   Size: %s\n", formatBytes(diskInfo.Size))
	fmt.Printf("   Available: %s\n", formatBytes(diskInfo.Available))
	fmt.Printf("   Used: %s\n", formatBytes(diskInfo.Used))

	logger.Info("Local storage volume created successfully",
		zap.String("device", diskInfo.Device),
		zap.String("mount_point", diskInfo.MountPoint),
		zap.Int64("size", diskInfo.Size))

	return nil
}
