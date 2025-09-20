// cmd/read/disk_usage.go
package read

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

var diskUsageCmd = &cobra.Command{
	Use:     "disk-usage",
	Aliases: []string{"disk-space", "df"},
	Short:   "Show disk usage for mounted filesystems",
	Long: `Show disk usage information for all mounted filesystems.

Displays filesystem, size, used space, available space, and usage percentage.

Examples:
  eos read disk-usage                   # Show disk usage
  eos read disk-usage --json           # Output in JSON format`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Getting disk usage information")

		outputJSON, _ := cmd.Flags().GetBool("json")

		// TODO: Implement GetDiskUsage method or use alternative approach
		usage := make(map[string]storage.DiskUsageInfo)
		err := fmt.Errorf("GetDiskUsage not yet implemented in consolidated storage package")
		if err != nil {
			logger.Error("Failed to get disk usage", zap.Error(err))
			return err
		}

		if outputJSON {
			return outputDiskUsageJSON(usage)
		}

		return outputDiskUsageTable(rc, usage)
	}),
}

func init() {
	diskUsageCmd.Flags().Bool("json", false, "Output in JSON format")

	ReadCmd.AddCommand(diskUsageCmd)
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputDiskUsageJSON(usage map[string]storage.DiskUsageInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(usage)
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputDiskUsageTable(rc *eos_io.RuntimeContext, usage map[string]storage.DiskUsageInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	if len(usage) == 0 {
		logger.Info("terminal prompt: No mounted filesystems found.")
		return nil
	}

	logger.Info(fmt.Sprintf("terminal prompt: Disk Usage Information (%d filesystems)", len(usage)))

	// Print header
	fmt.Printf("%-20s %-10s %-10s %-10s %-8s %s\n",
		"FILESYSTEM", "SIZE", "USED", "AVAIL", "USE%", "MOUNTED ON")
	logger.Info("terminal prompt: " + strings.Repeat("-", 80))

	// Print usage information
	for _, info := range usage {
		fmt.Printf("%-20s %-10d %-10d %-10d %-8.1f%% %s\n",
			utils.TruncateString(info.Filesystem, 20),
			info.Size,
			info.Used,
			info.Available,
			info.UsePercent,
			info.Mountpoint)
	}

	return nil
}
