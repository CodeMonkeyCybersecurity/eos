package create

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/udisks2"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/utils"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var storageUdisks2Cmd = &cobra.Command{
	Use:   "storage-udisks2",
	Short: "Create storage volumes using D-Bus/udisks2",
	Long: `Create and manage storage volumes safely using D-Bus/udisks2 integration.
This command provides safe disk operations without requiring root privileges
by leveraging the udisks2 system service via D-Bus.

Examples:
  # Create a simple ext4 volume
  eos create storage-udisks2 --device /dev/sdb --filesystem ext4 --label data

  # Create an encrypted volume with custom mount point
  eos create storage-udisks2 --device /dev/sdc --filesystem xfs --encrypted --mount-point /mnt/secure

  # Create a volume with specific size (leave rest unpartitioned)
  eos create storage-udisks2 --device /dev/sdd --size 50GB --filesystem btrfs --label backup`,
	RunE: eos_cli.Wrap(createStorageUdisks2),
}

var (
	udisks2Device      string
	udisks2Size        string
	udisks2Filesystem  string
	udisks2Label       string
	udisks2MountPoint  string
	udisks2MountOptions []string
	udisks2Encrypted   bool
	udisks2Passphrase  string
	udisks2Force       bool
	udisks2DryRun      bool
)

func init() {
	storageUdisks2Cmd.Flags().StringVar(&udisks2Device, "device", "", "Target block device (e.g., /dev/sdb)")
	storageUdisks2Cmd.Flags().StringVar(&udisks2Size, "size", "", "Volume size (e.g., 10GB, 500MB, or empty for full device)")
	storageUdisks2Cmd.Flags().StringVar(&udisks2Filesystem, "filesystem", "ext4", "Filesystem type (ext4, xfs, btrfs)")
	storageUdisks2Cmd.Flags().StringVar(&udisks2Label, "label", "", "Volume label")
	storageUdisks2Cmd.Flags().StringVar(&udisks2MountPoint, "mount-point", "", "Mount point (auto-mount if specified)")
	storageUdisks2Cmd.Flags().StringSliceVar(&udisks2MountOptions, "mount-options", []string{}, "Mount options (comma-separated)")
	storageUdisks2Cmd.Flags().BoolVar(&udisks2Encrypted, "encrypted", false, "Enable volume encryption")
	storageUdisks2Cmd.Flags().StringVar(&udisks2Passphrase, "passphrase", "", "Encryption passphrase (prompt if not provided)")
	storageUdisks2Cmd.Flags().BoolVar(&udisks2Force, "force", false, "Force operation even if device has existing data")
	storageUdisks2Cmd.Flags().BoolVar(&udisks2DryRun, "dry-run", false, "Show what would be done without executing")

	storageUdisks2Cmd.MarkFlagRequired("device")
}

func createStorageUdisks2(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting storage udisks2 creation", zap.String("command", "create_storage_udisks2"))

	logger.Info("Creating storage volume with udisks2",
		zap.String("device", udisks2Device),
		zap.String("filesystem", udisks2Filesystem),
		zap.String("size", udisks2Size),
		zap.Bool("encrypted", udisks2Encrypted),
		zap.Bool("dry_run", udisks2DryRun))

	// Parse size if provided
	var sizeBytes uint64
	if udisks2Size != "" {
		var err error
		sizeBytes, err = parseSize(udisks2Size)
		if err != nil {
			return fmt.Errorf("invalid size format: %w", err)
		}
	}

	// Handle encryption passphrase
	if udisks2Encrypted && udisks2Passphrase == "" {
		// In a real implementation, you'd prompt for passphrase securely
		return fmt.Errorf("passphrase required for encrypted volumes (use --passphrase flag)")
	}

	// Create volume request
	request := &udisks2.VolumeRequest{
		Device:       udisks2Device,
		Size:         sizeBytes,
		Filesystem:   udisks2Filesystem,
		Label:        udisks2Label,
		MountPoint:   udisks2MountPoint,
		Options: udisks2MountOptions,
		Encrypted:    udisks2Encrypted,
		Passphrase:   udisks2Passphrase,
		Metadata: map[string]string{
			"created_by": "eos",
			"created_at": time.Now().Format(time.RFC3339),
		},
	}

	if udisks2DryRun {
		return showDryRun(rc, request)
	}

	// Create disk manager
	diskMgr, err := udisks2.NewDiskManager(rc)
	if err != nil {
		return fmt.Errorf("failed to initialize disk operations: %w", err)
	}
	defer func() { _ = diskMgr.Close() }()

	// Check device safety if not forced
	if !udisks2Force {
		err = checkDeviceSafety(rc.Ctx, diskMgr, udisks2Device)
		if err != nil {
			return fmt.Errorf("device safety check failed: %w (use --force to override)", err)
		}
	}

	// Create volume
	logger.Info("Creating volume...")
	volumeInfo, err := diskMgr.CreateVolume(rc.Ctx, request)
	if err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	// Display results
	displayVolumeInfo(rc, volumeInfo)

	logger.Info("Storage volume created successfully",
		zap.String("device", volumeInfo.Device),
		zap.String("uuid", volumeInfo.UUID),
		zap.String("mount_point", volumeInfo.MountPoint))

	return nil
}

func parseSize(sizeStr string) (uint64, error) {
	sizeStr = strings.ToUpper(strings.TrimSpace(sizeStr))
	
	var multiplier uint64 = 1
	var numStr string

	if strings.HasSuffix(sizeStr, "TB") {
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "TB")
	} else if strings.HasSuffix(sizeStr, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "GB")
	} else if strings.HasSuffix(sizeStr, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "MB")
	} else if strings.HasSuffix(sizeStr, "KB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(sizeStr, "KB")
	} else if strings.HasSuffix(sizeStr, "B") {
		numStr = strings.TrimSuffix(sizeStr, "B")
	} else {
		numStr = sizeStr
	}

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number format: %s", numStr)
	}

	return uint64(num * float64(multiplier)), nil
}

func checkDeviceSafety(ctx context.Context, diskMgr *udisks2.DiskManager, device string) error {
	// Discover disks to check if device is in use
	disks, err := diskMgr.DiscoverDisks(ctx)
	if err != nil {
		return fmt.Errorf("failed to list volumes: %w", err)
	}

	for _, disk := range disks {
		if strings.HasPrefix(disk.Device, device) {
			// Check if any partitions are mounted
			for _, partition := range disk.Partitions {
				if partition.MountPoint != "" {
					return fmt.Errorf("device %s has mounted partitions", device)
				}
			}
		}
	}

	return nil
}

func showDryRun(_ *eos_io.RuntimeContext, request *udisks2.VolumeRequest) error {
	fmt.Println("=== DRY RUN MODE ===")
	fmt.Printf("Would create volume with the following configuration:\n\n")
	fmt.Printf("Device:       %s\n", request.Device)
	fmt.Printf("Size:         %s\n", utils.FormatBytes(request.Size))
	fmt.Printf("Filesystem:   %s\n", request.Filesystem)
	fmt.Printf("Label:        %s\n", request.Label)
	fmt.Printf("Mount Point:  %s\n", request.MountPoint)
	fmt.Printf("Encrypted:    %t\n", request.Encrypted)
	
	if len(request.Options) > 0 {
		fmt.Printf("Mount Options: %s\n", strings.Join(request.Options, ","))
	}

	fmt.Printf("\nOperations that would be performed:\n")
	fmt.Printf("1. Validate device %s\n", request.Device)
	fmt.Printf("2. Create partition table (GPT)\n")
	
	if request.Size > 0 {
		fmt.Printf("3. Create partition of size %s\n", utils.FormatBytes(request.Size))
	} else {
		fmt.Printf("3. Create partition using full device\n")
	}
	
	if request.Encrypted {
		fmt.Printf("4. Setup LUKS encryption\n")
		fmt.Printf("5. Create %s filesystem on encrypted device\n", request.Filesystem)
	} else {
		fmt.Printf("4. Create %s filesystem\n", request.Filesystem)
	}
	
	if request.MountPoint != "" {
		fmt.Printf("5. Mount at %s\n", request.MountPoint)
	}

	fmt.Printf("\nNo changes were made. Use --dry-run=false to execute.\n")
	return nil
}

func displayVolumeInfo(_ *eos_io.RuntimeContext, volume *udisks2.VolumeInfo) {
	fmt.Printf("\n=== Volume Created Successfully ===\n\n")
	fmt.Printf("Device:       %s\n", volume.Device)
	fmt.Printf("UUID:         %s\n", volume.UUID)
	fmt.Printf("Label:        %s\n", volume.Label)
	fmt.Printf("Filesystem:   %s\n", volume.Filesystem)
	fmt.Printf("Size:         %s\n", utils.FormatBytes(volume.Size))
	fmt.Printf("Encrypted:    %t\n", volume.Encrypted)
	fmt.Printf("Status:       %s\n", volume.Status)
	
	if volume.MountPoint != "" {
		fmt.Printf("Mount Point:  %s\n", volume.MountPoint)
	} else {
		fmt.Printf("Mount Point:  (not mounted)\n")
	}
	
	fmt.Printf("Created:      %s\n", volume.CreatedAt.Format(time.RFC3339))

	if volume.MountPoint != "" {
		fmt.Printf("\nVolume is ready for use at: %s\n", volume.MountPoint)
	} else {
		fmt.Printf("\nTo mount the volume:\n")
		fmt.Printf("  eos mount %s /your/mount/point\n", volume.Device)
	}
}

