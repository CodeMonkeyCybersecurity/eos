// cmd/list/disks.go
package list

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/disk_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var disksCmd = &cobra.Command{
	Use:     "disks",
	Aliases: []string{"disk", "disk-devices"},
	Short:   "List all available disk devices",
	Long: `List all available disk devices with their properties.

Shows device name, size, vendor, model, and mount points for each disk.

Examples:
  eos list disks                        # List all disks
  eos list disks --json               # Output in JSON format`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Listing disk devices")

		outputJSON, _ := cmd.Flags().GetBool("json")

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

func init() {
	disksCmd.Flags().Bool("json", false, "Output in JSON format")

	ListCmd.AddCommand(disksCmd)
}

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
