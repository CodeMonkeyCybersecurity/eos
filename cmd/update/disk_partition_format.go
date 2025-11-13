// cmd/update/disk_partition_format.go
package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var diskPartitionFormatCmd = &cobra.Command{
	Use:     "disk-partition-format <device>",
	Aliases: []string{"format-partition", "disk-format"},
	Short:   "Format a partition with a filesystem",
	Long: `Format a partition with the specified filesystem.

CAUTION: This operation will destroy all data on the partition.

Supported filesystems: ext4, ext3, xfs, btrfs

Examples:
  eos update disk-partition-format /dev/sdb1                  # Format as ext4 (default)
  eos update disk-partition-format /dev/sdb1 --fs xfs        # Format as XFS
  eos update disk-partition-format /dev/sdb1 --label DATA    # Format with label
  eos update disk-partition-format /dev/sdb1 --dry-run       # Show what would be done`,

	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// CRITICAL: Detect flag-like args (P0-1 fix)
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}
		device := args[0]

		filesystem, _ := cmd.Flags().GetString("fs")
		label, _ := cmd.Flags().GetString("label")
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		outputJSON, _ := cmd.Flags().GetBool("json")

		logger.Info("Formatting partition",
			zap.String("device", device),
			zap.String("filesystem", filesystem),
			zap.String("label", label),
			zap.Bool("dry_run", dryRun))

		if !force && !dryRun {
			logger.Info("terminal prompt: WARNING: This will destroy all data on device!", zap.String("device", device))
		}

		// Use simplified function instead of manager pattern
		result, err := storage.FormatPartition(rc, device, filesystem, label, dryRun)
		if err != nil {
			logger.Error("Failed to format partition", zap.Error(err))
			return err
		}

		if outputJSON {
			return storage.OutputFormatOpJSON(result)
		}

		return storage.OutputFormatOpText(result)
	}),
}

func init() {
	diskPartitionFormatCmd.Flags().String("fs", "ext4", "Filesystem type (ext4, ext3, xfs, btrfs)")
	diskPartitionFormatCmd.Flags().String("label", "", "Filesystem label")
	diskPartitionFormatCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompts")
	diskPartitionFormatCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	diskPartitionFormatCmd.Flags().Bool("json", false, "Output in JSON format")

	UpdateCmd.AddCommand(diskPartitionFormatCmd)
}
