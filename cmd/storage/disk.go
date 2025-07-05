package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/disk_management"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewDiskCmd creates the disk management command
func NewDiskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "disk",
		Aliases: []string{"disks", "partition"},
		Short:   "Manage disk devices and partitions",
		Long: `Manage disk devices and partitions including listing, partitioning, formatting, and mounting.

This command provides comprehensive disk management functionality similar to the 
original diskManager.mjs script but with enhanced safety features and Go integration.

Examples:
  eos storage disk list                           # List all available disks
  eos storage disk create /dev/sdb                # Create partition on disk
  eos storage disk format /dev/sdb1 --fs ext4     # Format partition as ext4
  eos storage disk mount /dev/sdb1 /mnt/data      # Mount partition
  eos storage disk usage                          # Show disk usage`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			otelzap.Ctx(rc.Ctx).Info("No subcommand provided for disk command")
			_ = cmd.Help()
			return nil
		}),
	}

	// Add subcommands
	cmd.AddCommand(newDiskListCmd())
	cmd.AddCommand(newDiskCreateCmd())
	cmd.AddCommand(newDiskFormatCmd())
	cmd.AddCommand(newDiskMountCmd())
	cmd.AddCommand(newDiskUsageCmd())

	return cmd
}

// newDiskListCmd creates the disk list subcommand
func newDiskListCmd() *cobra.Command {
	var outputJSON bool

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all available disk devices",
		Long: `List all available disk devices with their properties.

Shows device name, size, vendor, model, and mount points for each disk.

Examples:
  eos storage disk list                          # List all disks
  eos storage disk list --json                  # Output in JSON format`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Listing disk devices")

			manager := disk_management.NewDiskManager(nil)
			result, err := manager.ListDisks(rc)
			if err != nil {
				logger.Error("Failed to list disks", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputDiskListJSON(result)
			}

			return outputDiskListTable(result)
		}),
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// newDiskCreateCmd creates the partition creation subcommand
func newDiskCreateCmd() *cobra.Command {
	var (
		partitionType string
		force         bool
		dryRun        bool
		outputJSON    bool
	)

	cmd := &cobra.Command{
		Use:   "create <device>",
		Short: "Create a new partition on a disk",
		Long: `Create a new partition on the specified disk device.

This operation will create a primary partition using the entire available space.
CAUTION: This will modify the partition table and may destroy data.

Examples:
  eos storage disk create /dev/sdb                      # Create partition on /dev/sdb
  eos storage disk create /dev/sdb --dry-run            # Show what would be done
  eos storage disk create /dev/sdb --force              # Skip confirmation
  eos storage disk create /dev/sdb --type extended      # Create extended partition`,

		Args: cobra.ExactArgs(1),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			device := args[0]

			logger.Info("Creating partition", 
				zap.String("device", device),
				zap.String("type", partitionType),
				zap.Bool("dry_run", dryRun))

			options := disk_management.DefaultPartitionOptions()
			options.PartitionType = partitionType
			options.Force = force
			options.DryRun = dryRun

			manager := disk_management.NewDiskManager(nil)
			result, err := manager.CreatePartition(rc, device, options)
			if err != nil {
				logger.Error("Failed to create partition", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputPartitionOpJSON(result)
			}

			return outputPartitionOpText(result)
		}),
	}

	cmd.Flags().StringVar(&partitionType, "type", "primary", "Partition type (primary, extended, logical)")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompts")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// newDiskFormatCmd creates the format subcommand
func newDiskFormatCmd() *cobra.Command {
	var (
		filesystem string
		label      string
		force      bool
		dryRun     bool
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "format <device>",
		Short: "Format a partition with a filesystem",
		Long: `Format a partition with the specified filesystem.

CAUTION: This operation will destroy all data on the partition.

Supported filesystems: ext4, ext3, xfs, btrfs

Examples:
  eos storage disk format /dev/sdb1                     # Format as ext4 (default)
  eos storage disk format /dev/sdb1 --fs xfs           # Format as XFS
  eos storage disk format /dev/sdb1 --label DATA       # Format with label
  eos storage disk format /dev/sdb1 --dry-run          # Show what would be done`,

		Args: cobra.ExactArgs(1),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			device := args[0]

			logger.Info("Formatting partition", 
				zap.String("device", device),
				zap.String("filesystem", filesystem),
				zap.String("label", label),
				zap.Bool("dry_run", dryRun))

			if !force && !dryRun {
				fmt.Printf("WARNING: This will destroy all data on %s!\n", device)
			}

			manager := disk_management.NewDiskManager(nil)
			result, err := manager.FormatPartition(rc, device, filesystem, label, dryRun)
			if err != nil {
				logger.Error("Failed to format partition", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputFormatOpJSON(result)
			}

			return outputFormatOpText(result)
		}),
	}

	cmd.Flags().StringVar(&filesystem, "fs", "ext4", "Filesystem type (ext4, ext3, xfs, btrfs)")
	cmd.Flags().StringVar(&label, "label", "", "Filesystem label")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompts")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// newDiskMountCmd creates the mount subcommand
func newDiskMountCmd() *cobra.Command {
	var (
		options    string
		dryRun     bool
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "mount <device> <mountpoint>",
		Short: "Mount a partition to a mount point",
		Long: `Mount a partition to the specified mount point.

The mount point directory will be created if it doesn't exist.

Examples:
  eos storage disk mount /dev/sdb1 /mnt/data            # Mount partition
  eos storage disk mount /dev/sdb1 /mnt/data --options ro  # Mount read-only
  eos storage disk mount /dev/sdb1 /mnt/data --dry-run     # Show what would be done`,

		Args: cobra.ExactArgs(2),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			device := args[0]
			mountPoint := args[1]

			logger.Info("Mounting partition", 
				zap.String("device", device),
				zap.String("mount_point", mountPoint),
				zap.String("options", options),
				zap.Bool("dry_run", dryRun))

			manager := disk_management.NewDiskManager(nil)
			result, err := manager.MountPartition(rc, device, mountPoint, options, dryRun)
			if err != nil {
				logger.Error("Failed to mount partition", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputMountOpJSON(result)
			}

			return outputMountOpText(result)
		}),
	}

	cmd.Flags().StringVarP(&options, "options", "o", "", "Mount options (e.g., ro, rw, noexec)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// newDiskUsageCmd creates the disk usage subcommand
func newDiskUsageCmd() *cobra.Command {
	var outputJSON bool

	cmd := &cobra.Command{
		Use:     "usage",
		Aliases: []string{"df"},
		Short:   "Show disk usage for mounted filesystems",
		Long: `Show disk usage information for all mounted filesystems.

Displays filesystem, size, used space, available space, and usage percentage.

Examples:
  eos storage disk usage                         # Show disk usage
  eos storage disk usage --json                 # Output in JSON format`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Getting disk usage information")

			manager := disk_management.NewDiskManager(nil)
			usage, err := manager.GetDiskUsage(rc)
			if err != nil {
				logger.Error("Failed to get disk usage", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputDiskUsageJSON(usage)
			}

			return outputDiskUsageTable(usage)
		}),
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// Output formatting functions

func outputDiskListJSON(result *disk_management.DiskListResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputDiskListTable(result *disk_management.DiskListResult) error {
	if result.Total == 0 {
		fmt.Println("No disk devices found.")
		return nil
	}

	fmt.Printf("Found %d disk devices\n", result.Total)
	fmt.Printf("Listed at: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	// Print header
	fmt.Printf("%-12s %-15s %-10s %-15s %-15s %s\n", 
		"DEVICE", "NAME", "SIZE", "VENDOR", "MODEL", "MOUNT POINTS")
	fmt.Println(strings.Repeat("-", 90))

	// Print disks
	for _, disk := range result.Disks {
		mountPoints := "-"
		if len(disk.Mountpoints) > 0 {
			var points []string
			for _, mp := range disk.Mountpoints {
				points = append(points, mp.Path)
			}
			mountPoints = strings.Join(points, ",")
		}

		fmt.Printf("%-12s %-15s %-10s %-15s %-15s %s\n",
			disk.Device,
			truncateString(disk.Name, 15),
			disk.SizeHuman,
			truncateString(disk.Vendor, 15),
			truncateString(disk.Model, 15),
			truncateString(mountPoints, 25))
	}

	return nil
}

func outputPartitionOpJSON(result *disk_management.PartitionOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputPartitionOpText(result *disk_management.PartitionOperation) error {
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}

func outputFormatOpJSON(result *disk_management.FormatOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputFormatOpText(result *disk_management.FormatOperation) error {
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}

func outputMountOpJSON(result *disk_management.MountOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputMountOpText(result *disk_management.MountOperation) error {
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}

func outputDiskUsageJSON(usage map[string]disk_management.DiskUsageInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(usage)
}

func outputDiskUsageTable(usage map[string]disk_management.DiskUsageInfo) error {
	if len(usage) == 0 {
		fmt.Println("No mounted filesystems found.")
		return nil
	}

	fmt.Printf("Disk Usage Information (%d filesystems)\n\n", len(usage))

	// Print header
	fmt.Printf("%-20s %-10s %-10s %-10s %-8s %s\n", 
		"FILESYSTEM", "SIZE", "USED", "AVAIL", "USE%", "MOUNTED ON")
	fmt.Println(strings.Repeat("-", 80))

	// Print usage information
	for _, info := range usage {
		fmt.Printf("%-20s %-10s %-10s %-10s %-8s %s\n",
			truncateString(info.Filesystem, 20),
			info.Size,
			info.Used,
			info.Available,
			info.UsePercent,
			info.MountPoint)
	}

	return nil
}

// Helper function
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}