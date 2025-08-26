package read

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/output"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/monitor"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var readStorageStatusCmd = &cobra.Command{
	Use:   "storage-status",
	Short: "Read storage status and usage information",
	Long: `Display comprehensive storage status including disk usage, mount points, 
and filesystem information for all storage devices.

This command provides a detailed view of storage utilization across all mounted
filesystems, helping administrators monitor disk space and plan for capacity.

Features:
  - Shows filesystem usage statistics (size, used, available)
  - Displays mount points and device information
  - Optional inode usage information
  - Filters pseudo filesystems by default
  - Multiple output formats (table, JSON, YAML)

Default behavior:
  - Checks root filesystem (/)
  - Excludes pseudo filesystems (proc, sysfs, tmpfs, etc.)
  - Displays human-readable sizes

Examples:
  # Check storage status for root filesystem
  eos read storage-status
  
  # Check multiple paths
  eos read storage-status --paths /,/home,/var
  
  # Include all filesystems (including pseudo)
  eos read storage-status --all
  
  # Show inode usage information
  eos read storage-status --inodes
  
  # Output as JSON
  eos read storage-status --format json
  
  # Output as YAML
  eos read storage-status --format yaml`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		paths, _ := cmd.Flags().GetStringSlice("paths")
		showAll, _ := cmd.Flags().GetBool("all")
		showInodes, _ := cmd.Flags().GetBool("inodes")
		format, _ := cmd.Flags().GetString("format")

		logger.Info("Reading storage status",
			zap.Strings("paths", paths),
			zap.Bool("all", showAll))

		// Get disk usage
		usage, err := monitor.CheckDiskUsage(rc, paths)
		if err != nil {
			return fmt.Errorf("failed to check disk usage: %w", err)
		}

		// Filter out pseudo filesystems unless --all
		if !showAll {
			filtered := make([]monitor.DiskUsage, 0)
			for _, u := range usage {
				if !utils.IsPseudoFilesystem(u.Filesystem) {
					filtered = append(filtered, u)
				}
			}
			usage = filtered
		}

		// Output based on format
		switch format {
		case "json":
			return output.JSONToStdout(usage)
		case "yaml":
			return output.YAMLToStdout(usage)
		default:
			return output.DiskUsageTable(usage, showInodes)
		}
	}),
}

func init() {
	readStorageStatusCmd.Flags().StringSlice("paths", []string{"/"}, "Paths to check")
	readStorageStatusCmd.Flags().Bool("all", false, "Show all filesystems including pseudo")
	readStorageStatusCmd.Flags().Bool("inodes", false, "Show inode usage")
	readStorageStatusCmd.Flags().String("format", "table", "Output format: table, json, yaml")
}
