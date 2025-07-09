package read

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage_monitor"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var readStorageStatusCmd = &cobra.Command{
	Use:   "storage-status",
	Short: "Read storage status and usage information",
	Long: `Display comprehensive storage status including disk usage, mount points, 
and filesystem information for all storage devices.`,
	RunE: eos_cli.Wrap(runReadStorageStatus),
}

func init() {
	readStorageStatusCmd.Flags().StringSlice("paths", []string{"/"}, "Paths to check")
	readStorageStatusCmd.Flags().Bool("all", false, "Show all filesystems including pseudo")
	readStorageStatusCmd.Flags().Bool("inodes", false, "Show inode usage")
	readStorageStatusCmd.Flags().String("format", "table", "Output format: table, json, yaml")
}

func runReadStorageStatus(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	paths, _ := cmd.Flags().GetStringSlice("paths")
	showAll, _ := cmd.Flags().GetBool("all")
	showInodes, _ := cmd.Flags().GetBool("inodes")
	format, _ := cmd.Flags().GetString("format")

	logger.Info("Reading storage status",
		zap.Strings("paths", paths),
		zap.Bool("all", showAll))

	// Get disk usage
	usage, err := storage_monitor.CheckDiskUsage(rc, paths)
	if err != nil {
		return fmt.Errorf("failed to check disk usage: %w", err)
	}

	// Filter out pseudo filesystems unless --all
	if !showAll {
		filtered := make([]storage_monitor.DiskUsage, 0)
		for _, u := range usage {
			if !isPseudoFilesystem(u.Filesystem) {
				filtered = append(filtered, u)
			}
		}
		usage = filtered
	}

	// Output based on format
	switch format {
	case "json":
		return outputJSON(usage)
	case "yaml":
		return outputYAML(usage)
	default:
		return outputTable(usage, showInodes)
	}
}

func outputTable(usage []storage_monitor.DiskUsage, showInodes bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Header
	fmt.Fprintf(w, "FILESYSTEM\tDEVICE\tSIZE\tUSED\tAVAIL\tUSE%%\tMOUNTED ON\n")

	for _, u := range usage {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.1f%%\t%s\n",
			u.Filesystem,
			u.Device,
			formatBytes(u.TotalSize),
			formatBytes(u.UsedSize),
			formatBytes(u.AvailableSize),
			u.UsedPercent,
			u.Path)
	}

	w.Flush()

	if showInodes {
		fmt.Println("\nINODE USAGE:")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "FILESYSTEM\tINODES\tIUSED\tIFREE\tIUSE%%\n")

		for _, u := range usage {
			fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%.1f%%\n",
				u.Filesystem,
				u.InodesTotal,
				u.InodesUsed,
				u.InodesFree,
				u.InodesUsedPercent)
		}

		w.Flush()
	}

	return nil
}

func isPseudoFilesystem(fs string) bool {
	pseudo := []string{"proc", "sysfs", "devfs", "devpts", "tmpfs", "securityfs", "cgroup", "debugfs"}
	for _, p := range pseudo {
		if fs == p {
			return true
		}
	}
	return false
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
