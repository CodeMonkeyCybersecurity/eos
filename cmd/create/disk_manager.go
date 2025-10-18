package create

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/udisks2"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var diskManagerCmd = &cobra.Command{
	Use:   "disk",
	Short: "Manage physical disks using D-Bus/udisks2",
	Long: `Manage physical disks safely using D-Bus/udisks2 integration.
This command provides comprehensive disk management capabilities including:
- Disk discovery and enumeration
- Safe disk partitioning and formatting
- Filesystem creation (ext4, xfs, btrfs)
- Mount/unmount operations
- Disk health monitoring with SMART data
- Volume resizing and expansion
- Encryption support via LUKS

Examples:
  # Discover all available disks
  eos create disk discover

  # Create a volume on /dev/sdb with ext4 filesystem
  eos create disk volume --device /dev/sdb --size 100GB --filesystem ext4 --mount /mnt/data

  # Create encrypted volume
  eos create disk volume --device /dev/sdc --size 50GB --filesystem xfs --encrypted --mount /mnt/secure

  # Check disk health
  eos create disk health --device /dev/sda

  # Mount existing volume
  eos create disk mount --device /dev/sdb1 --mount /mnt/existing`,
	RunE: eos_cli.Wrap(runDiskManager),
}
// TODO: refactor
var (
	diskAction     string
	diskDevice     string
	diskSize       string
	diskFilesystem string
	diskLabel      string
	diskMountPoint string
	diskEncrypted  bool
	diskPassphrase string
	diskOptions    []string
	diskDryRun     bool
)

func init() {
	diskManagerCmd.Flags().StringVar(&diskAction, "action", "discover", "Action to perform (discover, volume, health, mount, unmount, resize)")
	diskManagerCmd.Flags().StringVar(&diskDevice, "device", "", "Target device (e.g., /dev/sdb)")
	diskManagerCmd.Flags().StringVar(&diskSize, "size", "0", "Volume size (e.g., 100GB, 50MB)")
	diskManagerCmd.Flags().StringVar(&diskFilesystem, "filesystem", "ext4", "Filesystem type (ext4, xfs, btrfs)")
	diskManagerCmd.Flags().StringVar(&diskLabel, "label", "", "Volume label")
	diskManagerCmd.Flags().StringVar(&diskMountPoint, "mount", "", "Mount point")
	diskManagerCmd.Flags().BoolVar(&diskEncrypted, "encrypted", false, "Enable LUKS encryption")
	diskManagerCmd.Flags().StringVar(&diskPassphrase, "passphrase", "", "Encryption passphrase (prompt if empty)")
	diskManagerCmd.Flags().StringSliceVar(&diskOptions, "options", []string{}, "Mount options")
	diskManagerCmd.Flags().BoolVar(&diskDryRun, "dry-run", false, "Show what would be done without executing")
}
// TODO: refactor
func runDiskManager(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting disk management operation",
		zap.String("action", diskAction),
		zap.String("device", diskDevice),
		zap.Bool("dry_run", diskDryRun))

	// Initialize disk manager
	diskMgr, err := udisks2.NewDiskManager(rc)
	if err != nil {
		return fmt.Errorf("failed to initialize disk manager: %w", err)
	}
	defer func() { _ = diskMgr.Close() }()

	switch diskAction {
	case "discover":
		return discoverDisks(rc, diskMgr)
	case "volume":
		return createDiskVolume(rc, diskMgr)
	case "health":
		return checkDiskHealth(rc, diskMgr)
	case "mount":
		return mountDiskVolume(rc, diskMgr)
	case "unmount":
		return unmountDiskVolume(rc, diskMgr)
	case "resize":
		return resizeDiskVolume(rc, diskMgr)
	default:
		return fmt.Errorf("unsupported action: %s", diskAction)
	}
}
// TODO: refactor
func discoverDisks(rc *eos_io.RuntimeContext, diskMgr *udisks2.DiskManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Discovering available disks")

	disks, err := diskMgr.DiscoverDisks(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to discover disks: %w", err)
	}

	fmt.Printf("📀 Discovered %d disk(s):\n\n", len(disks))

	for _, disk := range disks {
		fmt.Printf("Device: %s\n", disk.Device)
		fmt.Printf("  Size: %s\n", formatDiskSize(uint64(disk.Size)))
		fmt.Printf("  Model: %s\n", disk.Model)
		fmt.Printf("  Vendor: %s\n", disk.Vendor)
		fmt.Printf("  Serial: %s\n", disk.Serial)
		fmt.Printf("  Media Type: %s\n", disk.MediaType)
		fmt.Printf("  Connection: %s\n", disk.ConnectionBus)
		fmt.Printf("  Removable: %t\n", disk.Removable)
		fmt.Printf("  Health: %s\n", disk.Health.Status)

		if len(disk.Partitions) > 0 {
			fmt.Printf("  Partitions:\n")
			for _, part := range disk.Partitions {
				fmt.Printf("    %s: %s (%s) - %s\n",
					part.Device, formatDiskSize(part.Size), part.Filesystem, part.MountPoint)
			}
		}
		fmt.Println()
	}

	return nil
}
// TODO: refactor
func createDiskVolume(rc *eos_io.RuntimeContext, diskMgr *udisks2.DiskManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	if diskDevice == "" {
		return fmt.Errorf("device is required for volume creation")
	}

	// Parse size
	sizeBytes, err := parseDiskSize(diskSize)
	if err != nil {
		return fmt.Errorf("invalid size: %w", err)
	}

	logger.Info("Creating disk volume",
		zap.String("device", diskDevice),
		zap.Uint64("size", sizeBytes),
		zap.String("filesystem", diskFilesystem),
		zap.Bool("encrypted", diskEncrypted))

	if diskDryRun {
		fmt.Printf(" DRY RUN - Would create volume:\n")
		fmt.Printf("   Device: %s\n", diskDevice)
		fmt.Printf("   Size: %s\n", diskSize)
		fmt.Printf("   Filesystem: %s\n", diskFilesystem)
		fmt.Printf("   Label: %s\n", diskLabel)
		fmt.Printf("   Mount Point: %s\n", diskMountPoint)
		fmt.Printf("   Encrypted: %t\n", diskEncrypted)
		return nil
	}

	// Handle encryption passphrase
	passphrase := diskPassphrase
	if diskEncrypted && passphrase == "" {
		fmt.Print("Enter encryption passphrase: ")
		// In a real implementation, use a secure password input
		_, _ = fmt.Scanln(&passphrase)
	}

	volumeReq := &udisks2.VolumeRequest{
		Device:     diskDevice,
		Size:       sizeBytes,
		Filesystem: diskFilesystem,
		Label:      diskLabel,
		MountPoint: diskMountPoint,
		Encrypted:  diskEncrypted,
		Passphrase: passphrase,
		Options:    diskOptions,
		Metadata: map[string]string{
			"created_by": "eos-cli",
			"command":    "create_disk_volume",
		},
	}

	volumeInfo, err := diskMgr.CreateVolume(rc.Ctx, volumeReq)
	if err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	fmt.Printf(" Volume created successfully:\n")
	fmt.Printf("   Device: %s\n", volumeInfo.Device)
	fmt.Printf("   UUID: %s\n", volumeInfo.UUID)
	fmt.Printf("   Size: %s\n", formatDiskSize(volumeInfo.Size))
	fmt.Printf("   Filesystem: %s\n", volumeInfo.Filesystem)
	fmt.Printf("   Label: %s\n", volumeInfo.Label)
	fmt.Printf("   Mount Point: %s\n", volumeInfo.MountPoint)
	fmt.Printf("   Encrypted: %t\n", volumeInfo.Encrypted)
	fmt.Printf("   Status: %s\n", volumeInfo.Status)

	return nil
}
// TODO: refactor
func checkDiskHealth(rc *eos_io.RuntimeContext, diskMgr *udisks2.DiskManager) error {
	if diskDevice == "" {
		return fmt.Errorf("device is required for health check")
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking disk health", zap.String("device", diskDevice))

	health, err := diskMgr.GetDiskHealth(rc.Ctx, diskDevice)
	if err != nil {
		return fmt.Errorf("failed to get disk health: %w", err)
	}

	fmt.Printf("🏥 Disk Health Report for %s:\n\n", diskDevice)
	fmt.Printf("Overall Status: %s\n", health.Status)
	fmt.Printf("Temperature: %d°C\n", health.Temperature)
	fmt.Printf("Power-On Hours: %d\n", health.PowerOnHours)
	fmt.Printf("Last Check: %s\n", health.LastCheck.Format("2006-01-02 15:04:05"))

	if len(health.SmartData) > 0 {
		fmt.Printf("\nSMART Attributes:\n")
		for key, value := range health.SmartData {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}

	// Health recommendations
	switch health.Status {
	case "healthy":
		fmt.Printf("\n Disk appears to be in good health\n")
	case "warning":
		fmt.Printf("\nDisk shows warning signs - monitor closely\n")
	case "critical":
		fmt.Printf("\n Disk is in critical condition - backup data immediately\n")
	default:
		fmt.Printf("\n❓ Disk health status unknown\n")
	}

	return nil
}
// TODO: refactor
func mountDiskVolume(rc *eos_io.RuntimeContext, diskMgr *udisks2.DiskManager) error {
	if diskDevice == "" {
		return fmt.Errorf("device is required for mounting")
	}
	if diskMountPoint == "" {
		return fmt.Errorf("mount point is required")
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Mounting volume",
		zap.String("device", diskDevice),
		zap.String("mount_point", diskMountPoint))

	err := diskMgr.MountVolume(rc.Ctx, diskDevice, diskMountPoint, diskOptions)
	if err != nil {
		return fmt.Errorf("failed to mount volume: %w", err)
	}

	fmt.Printf(" Volume mounted successfully:\n")
	fmt.Printf("   Device: %s\n", diskDevice)
	fmt.Printf("   Mount Point: %s\n", diskMountPoint)

	return nil
}
// TODO: refactor
func unmountDiskVolume(rc *eos_io.RuntimeContext, diskMgr *udisks2.DiskManager) error {
	if diskDevice == "" {
		return fmt.Errorf("device is required for unmounting")
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Unmounting volume", zap.String("device", diskDevice))

	err := diskMgr.UnmountVolume(rc.Ctx, diskDevice)
	if err != nil {
		return fmt.Errorf("failed to unmount volume: %w", err)
	}

	fmt.Printf(" Volume unmounted successfully: %s\n", diskDevice)
	return nil
}
// TODO: refactor
func resizeDiskVolume(rc *eos_io.RuntimeContext, diskMgr *udisks2.DiskManager) error {
	if diskDevice == "" {
		return fmt.Errorf("device is required for resizing")
	}
	if diskSize == "" || diskSize == "0" {
		return fmt.Errorf("new size is required for resizing")
	}

	// Parse new size
	newSizeBytes, err := parseDiskSize(diskSize)
	if err != nil {
		return fmt.Errorf("invalid size: %w", err)
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Resizing volume",
		zap.String("device", diskDevice),
		zap.Uint64("new_size", newSizeBytes))

	if diskDryRun {
		fmt.Printf(" DRY RUN - Would resize volume:\n")
		fmt.Printf("   Device: %s\n", diskDevice)
		fmt.Printf("   New Size: %s\n", diskSize)
		return nil
	}

	err = diskMgr.ResizeVolume(rc.Ctx, diskDevice, newSizeBytes)
	if err != nil {
		return fmt.Errorf("failed to resize volume: %w", err)
	}

	fmt.Printf(" Volume resized successfully:\n")
	fmt.Printf("   Device: %s\n", diskDevice)
	fmt.Printf("   New Size: %s\n", diskSize)

	return nil
}
// TODO: refactor
// Helper functions
func parseDiskSize(size string) (uint64, error) {
	if size == "" || size == "0" {
		return 0, nil // Use entire device
	}

	size = strings.ToUpper(strings.TrimSpace(size))

	var multiplier uint64 = 1
	var numStr string

	if strings.HasSuffix(size, "TB") {
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "TB")
	} else if strings.HasSuffix(size, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "GB")
	} else if strings.HasSuffix(size, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(size, "MB")
	} else {
		numStr = size
	}

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, fmt.Errorf("invalid number format: %s", numStr)
	}

	return uint64(num * float64(multiplier)), nil
}
// TODO: refactor
func formatDiskSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
