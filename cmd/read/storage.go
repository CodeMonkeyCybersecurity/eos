// cmd/read/storage.go
package read

import (
	"fmt"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	showDevices  bool
	showLVM      bool
	showUsage    bool
	showAll      bool
	legacyOutput bool
)

// readStorageCmd represents the create command for storage
var ReadStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Retrieve information about storage devices and filesystem usage",
	Long: `Read and display information about storage resources including:
- Block devices and filesystems
- LVM volume groups and logical volumes  
- Disk usage and mounted filesystems

The command provides detailed storage analysis through multiple modes:
1. Block Devices: Lists all block devices with UUID, label, type, mountpoint, and size
2. LVM Information: Shows volume groups and logical volumes with detailed configuration
3. Disk Usage: Displays filesystem usage and available space
4. Legacy Mode: Uses traditional command output (lsblk, df -h) for compatibility

Storage information includes:
- Device identification and labeling
- Filesystem types and mount points
- Volume group and logical volume status
- Disk space utilization and availability
- Storage pool and device mappings

The modern output provides structured data with comprehensive logging,
while legacy mode offers traditional Unix command output for script compatibility.`,
	Example: `  # Show all storage information (default)
  eos read storage
  
  # Show only block devices
  eos read storage --devices
  
  # Show only LVM information
  eos read storage --lvm
  
  # Show only disk usage
  eos read storage --usage
  
  # Show all storage information explicitly
  eos read storage --all
  
  # Use legacy output format (lsblk, df -h)
  eos read storage --legacy
  
  # Example modern output:
  # - Structured device information with UUIDs
  # - LVM volume group and logical volume details
  # - Comprehensive disk usage analysis
  
  # Example legacy output:
  # - Traditional lsblk command output
  # - Standard df -h filesystem usage`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if legacyOutput {
			logger.Info("Reading storage information...")

			// Run lsblk
			logger.Info("\nBlock Devices (lsblk):")
			if err := runCommand(rc, "lsblk", "--all", "--output", "NAME,SIZE,TYPE,MOUNTPOINT"); err != nil {
				logger.Error("Error running lsblk", zap.Error(err))
				return err
			}

			// Run df -h
			logger.Info("\nFilesystem Usage (df -h):")
			if err := runCommand(rc, "df", "-h"); err != nil {
				logger.Error("Error running df -h", zap.Error(err))
				return err
			}
			return nil
		}

		if showAll || (!showDevices && !showLVM && !showUsage) {
			showDevices = true
			showLVM = true
			showUsage = true
		}

		if showDevices {
			logger.Info("=== Block Devices ===")
			devices, err := storage.ListBlockDevices(rc)
			if err != nil {
				logger.Error("Failed to list block devices", zap.Error(err))
			} else {
				for _, device := range devices {
					logger.Info(fmt.Sprintf("Device: %s", device.Name),
						zap.String("uuid", device.UUID),
						zap.String("label", device.Label),
						zap.String("type", device.Type),
						zap.String("mountpoint", device.Mountpoint),
						zap.String("size", device.Size))
				}
			}
			logger.Info("")
		}

		if showLVM {
			logger.Info("=== LVM Information ===")

			// Show volume groups
			if err := storage.DisplayVolumeGroups(rc); err != nil {
				logger.Error("Failed to display volume groups", zap.Error(err))
			}

			logger.Info("")

			// Show logical volumes
			if err := storage.DisplayLogicalVolumes(rc); err != nil {
				logger.Error("Failed to display logical volumes", zap.Error(err))
			}

			logger.Info("")
		}

		if showUsage {
			logger.Info("=== Disk Usage ===")
			usage, err := storage.GetDiskUsage(rc)
			if err != nil {
				logger.Error("Failed to get disk usage", zap.Error(err))
			} else {
				logger.Info(usage)
			}
		}

		return nil
	}),
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// runCommand executes a system command and prints its output
func runCommand(rc *eos_io.RuntimeContext, command string, args ...string) error {
	logger := otelzap.Ctx(rc.Ctx)
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v\nOutput: %s", err, string(output))
	}
	logger.Info("terminal prompt: " + string(output))
	return nil
}

// init registers subcommands for the read command
func init() {
	ReadCmd.AddCommand(ReadStorageCmd)

	ReadStorageCmd.Flags().BoolVar(&showDevices, "devices", false, "Show block devices and filesystems")
	ReadStorageCmd.Flags().BoolVar(&showLVM, "lvm", false, "Show LVM volume groups and logical volumes")
	ReadStorageCmd.Flags().BoolVar(&showUsage, "usage", false, "Show disk usage")
	ReadStorageCmd.Flags().BoolVar(&showAll, "all", false, "Show all storage information")
	ReadStorageCmd.Flags().BoolVar(&legacyOutput, "legacy", false, "Use legacy output format")
}
