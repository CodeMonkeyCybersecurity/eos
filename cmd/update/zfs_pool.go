// cmd/update/zfs_pool.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/zfs_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var zfsPoolCmd = &cobra.Command{
	Use:     "zfs-pool <pool> <device>",
	Aliases: []string{"zfs-expand", "zpool-expand"},
	Short:   "Expand a ZFS pool by adding a device",
	Long: `Add a device to an existing ZFS pool to expand its capacity.

The device will be added to the pool, increasing the available storage space.
This operation is non-destructive and does not affect existing data.

Examples:
  eos update zfs-pool mypool /dev/sdb                  # Add /dev/sdb to mypool
  eos update zfs-pool tank /dev/disk/by-id/scsi-123   # Add device by ID
  eos update zfs-pool --dry-run mypool /dev/sdc       # Preview the operation`,

	Args: cobra.ExactArgs(2),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")

		poolName := args[0]
		device := args[1]

		logger.Info("Expanding ZFS pool",
			zap.String("pool", poolName),
			zap.String("device", device),
			zap.Bool("dry_run", dryRun))

		config := &zfs_management.ZFSConfig{
			DryRun:  dryRun,
			Verbose: true,
			Force:   force,
		}

		manager := zfs_management.NewZFSManager(config)

		// Check if ZFS is available
		if err := manager.CheckZFSAvailable(rc); err != nil {
			return err
		}

		// Validate pool exists
		exists, err := manager.ValidatePoolExists(rc, poolName)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("ZFS pool '%s' does not exist", poolName)
		}

		result, err := manager.ExpandPool(rc, poolName, device)
		if err != nil {
			return err
		}

		return outputZFSOperationResult(result, outputJSON)
	}),
}

func init() {
	zfsPoolCmd.Flags().Bool("json", false, "Output in JSON format")
	zfsPoolCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	zfsPoolCmd.Flags().BoolP("force", "f", false, "Force the operation (use with caution)")

	UpdateCmd.AddCommand(zfsPoolCmd)
}
