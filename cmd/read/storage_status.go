package read

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage_monitor"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
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
	}),
}

func init() {
	readStorageStatusCmd.Flags().StringSlice("paths", []string{"/"}, "Paths to check")
	readStorageStatusCmd.Flags().Bool("all", false, "Show all filesystems including pseudo")
	readStorageStatusCmd.Flags().Bool("inodes", false, "Show inode usage")
	readStorageStatusCmd.Flags().String("format", "table", "Output format: table, json, yaml")
}

// TODO: HELPER_REFACTOR - Move to pkg/output/table.go
// Type: Output Formatter (Table)
// Related functions: outputJobsTable, other table formatters across cmd/
// Dependencies: imports fmt, text/tabwriter, os
// Note: This function violates CLAUDE.md by using fmt.Fprintf directly
// Should be part of a standardized table formatting package
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

// TODO: HELPER_REFACTOR - Move to pkg/utils/filesystem.go or pkg/storage_monitor/utils.go
// Type: Utility Function
// Related functions: Other filesystem utility functions
// Dependencies: none (pure function)
// Note: This is a general utility that could be reused across different commands
func isPseudoFilesystem(fs string) bool {
	pseudo := []string{"proc", "sysfs", "devfs", "devpts", "tmpfs", "securityfs", "cgroup", "debugfs"}
	for _, p := range pseudo {
		if fs == p {
			return true
		}
	}
	return false
}

// TODO: HELPER_REFACTOR - Move to pkg/output/json.go
// Type: Output Formatter
// Related functions: outputJobsJSON, outputJSONResult, other JSON formatters
// Dependencies: imports encoding/json, os
// Note: Consolidate with other JSON output functions
func outputJSON(usage []storage_monitor.DiskUsage) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(usage)
}

// TODO: HELPER_REFACTOR - Move to pkg/output/yaml.go
// Type: Output Formatter
// Related functions: Other YAML output functions across cmd/
// Dependencies: imports gopkg.in/yaml.v3, os
// Note: Create standardized YAML output formatter
func outputYAML(usage []storage_monitor.DiskUsage) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer encoder.Close()
	return encoder.Encode(usage)
}

// TODO: HELPER_REFACTOR - Move to pkg/utils/format.go or pkg/utils/units.go
// Type: Utility Function
// Related functions: Other byte/size formatting functions across cmd/
// Dependencies: imports fmt
// Note: This is a common utility used in many places for human-readable sizes
// Should be centralized to ensure consistent formatting
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
