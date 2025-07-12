// cmd/create/disk_partition.go
package create

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/disk_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var diskPartitionCmd = &cobra.Command{
	Use:     "disk-partition <device>",
	Aliases: []string{"partition", "disk-part"},
	Short:   "Create a new partition on a disk",
	Long: `Create a new partition on the specified disk device.

This operation will create a primary partition using the entire available space.
CAUTION: This will modify the partition table and may destroy data.

Examples:
  eos create disk-partition /dev/sdb                    # Create partition on /dev/sdb
  eos create disk-partition /dev/sdb --dry-run         # Show what would be done
  eos create disk-partition /dev/sdb --force           # Skip confirmation
  eos create disk-partition /dev/sdb --type extended   # Create extended partition`,

	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		device := args[0]

		partitionType, _ := cmd.Flags().GetString("type")
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		outputJSON, _ := cmd.Flags().GetBool("json")

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

func init() {
	diskPartitionCmd.Flags().String("type", "primary", "Partition type (primary, extended, logical)")
	diskPartitionCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompts")
	diskPartitionCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	diskPartitionCmd.Flags().Bool("json", false, "Output in JSON format")

	CreateCmd.AddCommand(diskPartitionCmd)
}

// TODO
func outputPartitionOpJSON(result *disk_management.PartitionOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// TODO
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
