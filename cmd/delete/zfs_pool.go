// cmd/delete/zfs_pool.go
package delete

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/zfs_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var zfsPoolCmd = &cobra.Command{
	Use:     "zfs-pool <pool>",
	Aliases: []string{"zpool", "zfs-storage-pool"},
	Short:   "Destroy a ZFS pool",
	Long: `Permanently destroy a ZFS pool and all its data.

WARNING: This operation is DESTRUCTIVE and will permanently delete all data!
Use with extreme caution and ensure you have backups of important data.

Examples:
  eos delete zfs-pool mypool              # Destroy entire pool
  eos delete zfs-pool --dry-run mypool    # Preview destruction
  eos delete zfs-pool --force mypool      # Force destruction (skip some checks)`,

	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		recursive, _ := cmd.Flags().GetBool("recursive")

		poolName := args[0]

		logger.Info("Destroying ZFS pool",
			zap.String("pool", poolName),
			zap.Bool("dry_run", dryRun),
			zap.Bool("force", force))

		config := &zfs_management.ZFSConfig{
			DryRun:    dryRun,
			Verbose:   true,
			Force:     force,
			Recursive: recursive,
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

		result, err := manager.DestroyPool(rc, poolName)
		if err != nil {
			return err
		}

		return storage.OutputZFSOperationResult(result, outputJSON)
	}),
}

func init() {
	zfsPoolCmd.Flags().Bool("json", false, "Output in JSON format")
	zfsPoolCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	zfsPoolCmd.Flags().BoolP("force", "f", false, "Force the operation (use with caution)")
	zfsPoolCmd.Flags().BoolP("recursive", "r", false, "Apply operation recursively")

	DeleteCmd.AddCommand(zfsPoolCmd)
}
