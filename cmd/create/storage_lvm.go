package create

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/lvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createStorageLVMCmd = &cobra.Command{
	Use:   "storage-lvm",
	Short: "Create LVM storage components",
	Long: `Create LVM storage components including physical volumes, volume groups, and logical volumes.
	
This command provides a complete LVM storage creation workflow optimized for different use cases,
including database storage on XFS for optimal performance.`,
}

var createLVMPVCmd = &cobra.Command{
	Use:   "pv [device]",
	Short: "Create an LVM physical volume",
	Long: `Create an LVM physical volume on the specified device.

This command initializes a block device for use with LVM. The device can be a disk,
partition, or any other block device. Once initialized as a physical volume (PV),
it can be added to a volume group.

Examples:
  # Create a physical volume on a disk
  eos create storage-lvm pv /dev/sdb
  
  # Create a physical volume with forced overwrite
  eos create storage-lvm pv /dev/sdc --force
  
  # Create a physical volume with custom UUID
  eos create storage-lvm pv /dev/sdd --uuid custom-uuid-here
  
  # Create a physical volume with data alignment
  eos create storage-lvm pv /dev/sde --data-alignment 1m`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		device := args[0]

		config := &lvm.PhysicalVolumeConfig{
			Device:        device,
			Force:         cmd.Flag("force").Value.String() == "true",
			UUID:          cmd.Flag("uuid").Value.String(),
			DataAlignment: cmd.Flag("data-alignment").Value.String(),
		}

		logger.Info("Creating LVM physical volume",
			zap.String("device", device),
			zap.Bool("force", config.Force))

		return lvm.CreatePhysicalVolume(rc, config)
	}),
}

var createLVMVGCmd = &cobra.Command{
	Use:   "vg [name] [devices...]",
	Short: "Create an LVM volume group",
	Long: `Create an LVM volume group from one or more physical volumes.

A volume group (VG) is a pool of storage that consists of one or more physical volumes.
Logical volumes are created from the free space in a volume group.

Examples:
  # Create a volume group from a single physical volume
  eos create storage-lvm vg datavg /dev/sdb1
  
  # Create a volume group from multiple physical volumes
  eos create storage-lvm vg webvg /dev/sdc1 /dev/sdd1
  
  # Create a volume group with custom extent size
  eos create storage-lvm vg fastvg /dev/nvme0n1p1 --extent-size 8M
  
  # Create a volume group with limits
  eos create storage-lvm vg limitedvg /dev/sde1 --max-lv 10 --max-pv 5`,
	Args: cobra.MinimumNArgs(2),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		name := args[0]
		pvs := args[1:]

		maxLV, _ := cmd.Flags().GetInt("max-lv")
		maxPV, _ := cmd.Flags().GetInt("max-pv")

		config := &lvm.VolumeGroupConfig{
			Name:               name,
			PhysicalVolumes:    pvs,
			ExtentSize:         cmd.Flag("extent-size").Value.String(),
			MaxLogicalVolumes:  maxLV,
			MaxPhysicalVolumes: maxPV,
		}

		logger.Info("Creating LVM volume group",
			zap.String("name", name),
			zap.Strings("pvs", pvs))

		return lvm.CreateVolumeGroup(rc, config)
	}),
}

var createLVMLVCmd = &cobra.Command{
	Use:   "lv [name]",
	Short: "Create an LVM logical volume",
	Long: `Create an LVM logical volume in an existing volume group.

Logical volumes (LVs) are the usable storage devices created from volume groups.
They can be formatted with filesystems and mounted like regular disk partitions.

This command supports various volume types including linear, striped, mirrored,
and RAID volumes. It can also automatically create and mount filesystems.

For database workloads on XFS, optimized mount options are automatically applied
when the volume name contains 'postgres' or 'db'.

Examples:
  # Create a 10GB logical volume
  eos create storage-lvm lv webdata -g webvg -L 10G
  
  # Create a logical volume with XFS filesystem
  eos create storage-lvm lv dbdata -g datavg -L 50G -f xfs
  
  # Create and mount a logical volume
  eos create storage-lvm lv appdata -g appvg -L 20G -f ext4 -m /mnt/appdata
  
  # Create a striped volume for performance
  eos create storage-lvm lv fastdata -g fastvg -L 100G --type striped --stripes 2
  
  # Create a database volume with optimized settings
  eos create storage-lvm lv postgres_data -g dbvg -L 100G -f xfs -m /var/lib/postgresql`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		name := args[0]

		vg := cmd.Flag("volume-group").Value.String()
		size := cmd.Flag("size").Value.String()
		lvType := cmd.Flag("type").Value.String()
		filesystem := cmd.Flag("filesystem").Value.String()
		mountPoint := cmd.Flag("mount").Value.String()
		mountOptions, _ := cmd.Flags().GetStringSlice("mount-options")
		stripes, _ := cmd.Flags().GetInt("stripes")

		config := &lvm.LogicalVolumeConfig{
			Name:         name,
			VolumeGroup:  vg,
			Size:         size,
			Type:         lvType,
			FileSystem:   filesystem,
			MountPoint:   mountPoint,
			MountOptions: mountOptions,
			Stripes:      stripes,
			StripeSize:   cmd.Flag("stripe-size").Value.String(),
		}

		logger.Info("Creating LVM logical volume",
			zap.String("name", name),
			zap.String("vg", vg),
			zap.String("size", size),
			zap.String("filesystem", filesystem))

		// Special handling for database volumes
		if filesystem == "xfs" && (strings.Contains(strings.ToLower(name), "postgres") || strings.Contains(strings.ToLower(name), "db")) {
			logger.Info("Detected database volume, using optimized XFS settings")
			if len(mountOptions) == 0 {
				config.MountOptions = lvm.XFSMountOptions["database"]
			}
		}

		return lvm.CreateLogicalVolume(rc, config)
	}),
}

func init() {
	// Add subcommands
	createStorageLVMCmd.AddCommand(createLVMPVCmd)
	createStorageLVMCmd.AddCommand(createLVMVGCmd)
	createStorageLVMCmd.AddCommand(createLVMLVCmd)

	// PV flags
	createLVMPVCmd.Flags().Bool("force", false, "Force creation even if filesystem exists")
	createLVMPVCmd.Flags().String("uuid", "", "Specify UUID for the physical volume")
	createLVMPVCmd.Flags().String("data-alignment", "", "Set data alignment")

	// VG flags
	createLVMVGCmd.Flags().String("extent-size", "4M", "Physical extent size")
	createLVMVGCmd.Flags().Int("max-lv", 0, "Maximum number of logical volumes")
	createLVMVGCmd.Flags().Int("max-pv", 0, "Maximum number of physical volumes")

	// LV flags
	createLVMLVCmd.Flags().StringP("volume-group", "g", "", "Volume group name (required)")
	createLVMLVCmd.Flags().StringP("size", "L", "", "Logical volume size (required)")
	createLVMLVCmd.Flags().String("type", "linear", "Volume type: linear, striped, mirror, raid, thin")
	createLVMLVCmd.Flags().StringP("filesystem", "f", "", "Create filesystem: ext4, xfs, btrfs")
	createLVMLVCmd.Flags().StringP("mount", "m", "", "Mount point for the volume")
	createLVMLVCmd.Flags().StringSlice("mount-options", []string{}, "Mount options")
	createLVMLVCmd.Flags().Int("stripes", 0, "Number of stripes for striped volumes")
	createLVMLVCmd.Flags().String("stripe-size", "64K", "Stripe size for striped volumes")

	if err := createLVMLVCmd.MarkFlagRequired("volume-group"); err != nil {
		panic(fmt.Sprintf("failed to mark volume-group flag as required: %v", err))
	}
	if err := createLVMLVCmd.MarkFlagRequired("size"); err != nil {
		panic(fmt.Sprintf("failed to mark size flag as required: %v", err))
	}
}
