// cmd/update/disk_mount.go
package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var diskMountCmd = &cobra.Command{
	Use:     "disk-mount <device> <mountpoint>",
	Aliases: []string{"mount-disk", "mount-partition"},
	Short:   "Mount a partition to a mount point",
	Long: `Mount a partition to the specified mount point.

The mount point directory will be created if it doesn't exist.

Examples:
  eos update disk-mount /dev/sdb1 /mnt/data           # Mount partition
  eos update disk-mount /dev/sdb1 /mnt/data --options ro  # Mount read-only
  eos update disk-mount /dev/sdb1 /mnt/data --dry-run     # Show what would be done`,

	Args: cobra.ExactArgs(2),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		device := args[0]
		mountPoint := args[1]

		options, _ := cmd.Flags().GetString("options")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		outputJSON, _ := cmd.Flags().GetBool("json")

		logger.Info("Mounting partition",
			zap.String("device", device),
			zap.String("mount_point", mountPoint),
			zap.String("options", options),
			zap.Bool("dry_run", dryRun))

		// Use simplified function instead of manager pattern
		result, err := storage.MountPartition(rc, device, mountPoint, options, dryRun)
		if err != nil {
			logger.Error("Failed to mount partition", zap.Error(err))
			return err
		}

		if outputJSON {
			return storage.OutputMountOpJSON(result)
		}

		return storage.OutputMountOpText(result)
	}),
}

func init() {
	diskMountCmd.Flags().StringP("options", "o", "", "Mount options (e.g., ro, rw, noexec)")
	diskMountCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	diskMountCmd.Flags().Bool("json", false, "Output in JSON format")

	UpdateCmd.AddCommand(diskMountCmd)
}
