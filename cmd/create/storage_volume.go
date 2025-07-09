// TODO: PATTERN 2 - Inline runCreateStorageVolume function into command RunE field
package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Storage volume creation command variables

var (
	// Flags for volume creation
	volumeName      string
	volumeType      string
	volumeSize      string
	volumeWorkload  string
	volumeFS        string
	volumeMountPath string
	volumeEncrypt   bool
	volumeCompress  bool
)

// createStorageVolumeCmd creates storage volumes with optimal settings
var createStorageVolumeCmd = &cobra.Command{
	Use:   "volume",
	Short: "Create a new storage volume",
	Long: `Create a new storage volume with optimal settings for your workload.

This command orchestrates storage creation through SaltStack, automatically
selecting the best storage type and filesystem based on your workload:

  - database: XFS on LVM for optimal random I/O
  - backup: BTRFS with compression and deduplication
  - container: ext4 on LVM for simplicity and reliability
  - distributed: CephFS for multi-node access

Examples:
  # Create a database volume
  eos create storage volume --name postgres-data --workload database --size 100G

  # Create a backup volume with compression
  eos create storage volume --name backups --workload backup --size 500G --compress

  # Create a specific type of volume
  eos create storage volume --name mydata --type lvm --fs xfs --size 200G --mount /data`,
	RunE: eos_cli.Wrap(runCreateStorageVolume),
}

func init() {
	CreateStorageCmd.AddCommand(createStorageVolumeCmd)

	// Volume configuration flags
	createStorageVolumeCmd.Flags().StringVarP(&volumeName, "name", "n", "", "Volume name (required)")
	createStorageVolumeCmd.Flags().StringVarP(&volumeType, "type", "t", "", "Storage type (lvm, btrfs, zfs, cephfs)")
	createStorageVolumeCmd.Flags().StringVarP(&volumeSize, "size", "s", "", "Volume size (e.g., 100G, 1T) (required)")
	createStorageVolumeCmd.Flags().StringVarP(&volumeWorkload, "workload", "w", "", "Workload type (database, backup, container, distributed)")
	createStorageVolumeCmd.Flags().StringVar(&volumeFS, "fs", "", "Filesystem type (ext4, xfs, btrfs, zfs)")
	createStorageVolumeCmd.Flags().StringVarP(&volumeMountPath, "mount", "m", "", "Mount path for the volume")
	createStorageVolumeCmd.Flags().BoolVar(&volumeEncrypt, "encrypt", false, "Enable encryption")
	createStorageVolumeCmd.Flags().BoolVar(&volumeCompress, "compress", false, "Enable compression (if supported)")

	// Mark required flags
	createStorageVolumeCmd.MarkFlagRequired("name")
	createStorageVolumeCmd.MarkFlagRequired("size")
}

func runCreateStorageVolume(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating storage volume",
		zap.String("name", volumeName),
		zap.String("size", volumeSize))

	// For now, pass nil for Salt client - in production this would be properly initialized
	// TODO: Initialize proper Salt client from configuration
	
	// Initialize unified storage manager
	storageManager, err := storage.NewUnifiedStorageManager(rc, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize storage manager: %w", err)
	}

	// Parse size to bytes
	sizeBytes, err := storage.ParseSize(volumeSize)
	if err != nil {
		return fmt.Errorf("invalid size format: %w", err)
	}

	// Build volume configuration
	config := storage.VolumeConfig{
		Name:       volumeName,
		Size:       sizeBytes,
		MountPoint: volumeMountPath,
		Encryption: volumeEncrypt,
	}

	// If workload is specified, get optimal configuration
	if volumeWorkload != "" {
		logger.Info("Using workload-optimized configuration",
			zap.String("workload", volumeWorkload))

		optimalConfig := storage.GetOptimalStorageForWorkload(volumeWorkload)

		// Merge with user-provided values
		config.Type = optimalConfig.Type
		config.Filesystem = optimalConfig.Filesystem
		config.MountOptions = optimalConfig.MountOptions
		config.Workload = volumeWorkload
		config.DriverConfig = optimalConfig.DriverConfig
	}

	// Override with explicit user values if provided
	if volumeType != "" {
		config.Type = storage.StorageType(volumeType)
	}
	if volumeFS != "" {
		config.Filesystem = storage.FilesystemType(volumeFS)
	}

	// Add compression to driver config if requested
	if volumeCompress {
		if config.DriverConfig == nil {
			config.DriverConfig = make(map[string]interface{})
		}
		config.DriverConfig["compression"] = "zstd"
		config.DriverConfig["compression_level"] = 3
	}

	// Validate configuration
	if config.Type == "" {
		config.Type = storage.StorageTypeLVM // Default to LVM
	}
	if config.Filesystem == "" {
		config.Filesystem = storage.FilesystemExt4 // Default to ext4
	}

	// Log the final configuration
	logger.Info("Volume configuration",
		zap.String("type", string(config.Type)),
		zap.String("filesystem", string(config.Filesystem)),
		zap.Int64("size_bytes", config.Size),
		zap.String("mount", config.MountPoint))

	// Create the volume through the unified manager
	volume, err := storageManager.CreateVolume(rc.Ctx, volumeName, config)
	if err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	// Display success message
	logger.Info("Volume created successfully",
		zap.String("id", volume.ID),
		zap.String("device", volume.Device),
		zap.String("mount_point", volume.MountPoint))

	// Print user-friendly output
	fmt.Printf("\n✓ Storage volume created successfully!\n\n")
	fmt.Printf("Volume Details:\n")
	fmt.Printf("  Name:       %s\n", volume.Name)
	fmt.Printf("  Type:       %s\n", volume.Type)
	fmt.Printf("  Device:     %s\n", volume.Device)
	fmt.Printf("  Size:       %s\n", storage.FormatSize(volume.TotalSize))
	fmt.Printf("  Filesystem: %s\n", volume.Filesystem)

	if volume.MountPoint != "" {
		fmt.Printf("  Mount:      %s\n", volume.MountPoint)
	}

	if volume.IsEncrypted {
		fmt.Printf("  Encryption: Enabled\n")
	}

	if config.DriverConfig["compression"] != nil {
		fmt.Printf("  Compression: %s\n", config.DriverConfig["compression"])
	}

	fmt.Printf("\nNext steps:\n")
	if volume.MountPoint == "" {
		fmt.Printf("  - Mount the volume: eos update storage mount %s --path /desired/path\n", volume.Name)
	}
	fmt.Printf("  - Check status: eos read storage status %s\n", volume.Name)
	fmt.Printf("  - Monitor health: eos read storage health %s\n", volume.Name)

	return nil
}
