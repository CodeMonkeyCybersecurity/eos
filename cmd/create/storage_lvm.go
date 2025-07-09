// TODO: PATTERN 2 - Inline runCreateLVMPV, runCreateLVMVG, runCreateLVMLV functions into their respective command RunE fields
package create

import (
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
	Args:  cobra.ExactArgs(1),
	RunE:  eos_cli.Wrap(runCreateLVMPV),
}

var createLVMVGCmd = &cobra.Command{
	Use:   "vg [name] [devices...]",
	Short: "Create an LVM volume group",
	Args:  cobra.MinimumNArgs(2),
	RunE:  eos_cli.Wrap(runCreateLVMVG),
}

var createLVMLVCmd = &cobra.Command{
	Use:   "lv [name]",
	Short: "Create an LVM logical volume",
	Args:  cobra.ExactArgs(1),
	RunE:  eos_cli.Wrap(runCreateLVMLV),
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

	createLVMLVCmd.MarkFlagRequired("volume-group")
	createLVMLVCmd.MarkFlagRequired("size")
}

func runCreateLVMPV(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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
}

func runCreateLVMVG(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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
}

func runCreateLVMLV(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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
}

