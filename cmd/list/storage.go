// cmd/list/disks.go
package list

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
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
		bootstrap, _ := cmd.Flags().GetBool("bootstrap")

		if bootstrap {
			logger.Info("Using bootstrap mode (direct execution without Salt)")
		} else {
			// For now, still use direct execution even without bootstrap flag
			// TODO: When Salt integration is ready, implement Salt-based disk listing
			logger.Info("Salt not configured, falling back to direct execution")
		}

		// Use simplified function instead of manager pattern
		result, err := storage.ListDisks(rc)
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
	disksCmd.Flags().Bool("bootstrap", false, "Use direct execution without Salt (for initial system discovery)")

	ListCmd.AddCommand(disksCmd)
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functinos
func outputDiskListJSON(result *storage.DiskListResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functinos
func outputDiskListTable(result *storage.DiskListResult) error {
	if result.Total == 0 {
		fmt.Println("No disk devices found.")
		return nil
	}

	fmt.Printf("Found %d disk devices\n", result.Total)
	fmt.Printf("Listed at: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))

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
			utils.TruncateString(disk.Name, 15),
			disk.SizeHuman,
			utils.TruncateString(disk.Vendor, 15),
			utils.TruncateString(disk.Model, 15),
			utils.TruncateString(mountPoints, 25))
	}

	return nil
}
