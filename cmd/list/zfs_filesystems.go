// cmd/list/zfs_filesystems.go
package list

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/zfs_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var zfsFilesystemsCmd = &cobra.Command{
	Use:     "zfs-filesystems",
	Aliases: []string{"zfs-filesystem", "zfs-fs", "zfs-datasets"},
	Short:   "List ZFS filesystems and datasets",
	Long: `List all ZFS filesystems and datasets with detailed information.

Shows filesystem name, used space, available space, referenced data, and mount points.

Examples:
  eos list zfs-filesystems              # List all ZFS filesystems
  eos list zfs-filesystems --json      # Output in JSON format`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Listing ZFS filesystems")

		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		config := &zfs_management.ZFSConfig{
			DryRun:  dryRun,
			Verbose: true,
		}

		manager := zfs_management.NewZFSManager(config)

		// Check if ZFS is available
		if err := manager.CheckZFSAvailable(rc); err != nil {
			return err
		}

		result, err := manager.ListFilesystems(rc)
		if err != nil {
			logger.Error("Failed to list ZFS filesystems", zap.Error(err))
			return err
		}

		return outputZFSFilesystemsResult(result, outputJSON)
	}),
}

func init() {
	zfsFilesystemsCmd.Flags().Bool("json", false, "Output in JSON format")
	zfsFilesystemsCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")

	ListCmd.AddCommand(zfsFilesystemsCmd)
}

func outputZFSFilesystemsResult(result *zfs_management.ZFSListResult, outputJSON bool) error {
	if outputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Text output
	if len(result.Filesystems) == 0 {
		fmt.Println("No ZFS filesystems found.")
		return nil
	}

	fmt.Printf("ZFS Filesystems (found %d):\n", result.Count)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("%-30s %-10s %-10s %-10s %-15s\n",
		"NAME", "USED", "AVAIL", "REFER", "MOUNTPOINT")
	fmt.Println(strings.Repeat("-", 80))

	for _, fs := range result.Filesystems {
		mountpoint := fs.Mountpoint
		if mountpoint == "" {
			mountpoint = "-"
		}
		fmt.Printf("%-30s %-10s %-10s %-10s %-15s\n",
			fs.Name, fs.Used, fs.Available, fs.Refer, mountpoint)
	}

	return nil
}
