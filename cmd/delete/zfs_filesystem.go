// cmd/delete/zfs_filesystem.go
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

var zfsFilesystemCmd = &cobra.Command{
	Use:     "zfs-filesystem <filesystem>",
	Aliases: []string{"zfs-fs", "zfs-dataset"},
	Short:   "Destroy a ZFS filesystem",
	Long: `Permanently destroy a ZFS filesystem or dataset.

WARNING: This operation is DESTRUCTIVE and will permanently delete all data!
Use with extreme caution and ensure you have backups of important data.

Examples:
  eos delete zfs-filesystem tank/data              # Destroy specific filesystem
  eos delete zfs-filesystem --dry-run tank/data   # Preview destruction
  eos delete zfs-filesystem --force tank/data     # Force destruction (skip some checks)`,

	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		recursive, _ := cmd.Flags().GetBool("recursive")

		filesystemName := args[0]

		logger.Info("Destroying ZFS filesystem",
			zap.String("filesystem", filesystemName),
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

		// Validate filesystem exists
		exists, err := manager.ValidateFilesystemExists(rc, filesystemName)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("ZFS filesystem '%s' does not exist", filesystemName)
		}

		result, err := manager.DestroyFilesystem(rc, filesystemName)
		if err != nil {
			return err
		}

		return storage.OutputZFSOperationResult(result, outputJSON)
	}),
}

func init() {
	zfsFilesystemCmd.Flags().Bool("json", false, "Output in JSON format")
	zfsFilesystemCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	zfsFilesystemCmd.Flags().BoolP("force", "f", false, "Force the operation (use with caution)")
	zfsFilesystemCmd.Flags().BoolP("recursive", "r", false, "Apply operation recursively")

	DeleteCmd.AddCommand(zfsFilesystemCmd)
}
