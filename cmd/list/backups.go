// cmd/list/backups.go

package list

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var backupsCmd = &cobra.Command{
	Use:     "backups",
	Short:   "List backup snapshots and repository metadata",
	Aliases: []string{"backup", "snap", "snapshots"},
	Long: `List backup snapshots with detailed metadata from restic repositories.

This command provides a comprehensive view of your backup snapshots including:
  - Snapshot ID, timestamp, and age
  - Hostname and paths backed up
  - Tags and parent snapshots
  - Statistics (file counts, sizes)
  - Repository health information

Examples:
  # List all snapshots in default repository
  eos list backups

  # List snapshots in specific repository
  eos list backups --repo remote

  # Show detailed metadata including statistics
  eos list backups --detailed

  # Filter by tags
  eos list backups --tags system,daily

  # Filter by hostname
  eos list backups --host server01

  # Show only the last N snapshots
  eos list backups --last 10

  # Group snapshots by host
  eos list backups --group-by host

  # Show repository statistics
  eos list backups --stats`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		repoName, _ := cmd.Flags().GetString("repo")
		filterTags, _ := cmd.Flags().GetStringSlice("tags")
		filterHost, _ := cmd.Flags().GetString("host")
		filterPath, _ := cmd.Flags().GetString("path")
		lastN, _ := cmd.Flags().GetInt("last")
		detailed, _ := cmd.Flags().GetBool("detailed")
		groupBy, _ := cmd.Flags().GetString("group-by")
		showStats, _ := cmd.Flags().GetBool("stats")

		// Use default repository if not specified
		if repoName == "" {
			config, err := backup.LoadConfig(rc)
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			repoName = config.DefaultRepository
			if repoName == "" {
				return fmt.Errorf("no repository specified and no default configured")
			}
		}

		logger.Info("Listing backup snapshots",
			zap.String("repository", repoName),
			zap.Strings("filter_tags", filterTags),
			zap.String("filter_host", filterHost),
			zap.Bool("detailed", detailed))

		// Create backup client
		client, err := backup.NewClient(rc, repoName)
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}

		// Get repository stats if requested
		if showStats {
			logger.Info("terminal prompt: \nRepository Statistics:")
			logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 80)))

			stats, err := client.GetStats()
			if err != nil {
				logger.Warn("Failed to get repository statistics", zap.Error(err))
			} else {
				displayRepositoryStats(logger, stats)
			}
			logger.Info("terminal prompt:", zap.String("output", ""))
		}

		// List snapshots
		snapshots, err := client.ListSnapshots()
		if err != nil {
			return fmt.Errorf("listing snapshots: %w", err)
		}

		// Apply filters
		filtered := filterSnapshots(snapshots, filterTags, filterHost, filterPath)

		// Apply last N limit
		if lastN > 0 && len(filtered) > lastN {
			filtered = filtered[len(filtered)-lastN:]
		}

		logger.Info("Found snapshots",
			zap.Int("total", len(snapshots)),
			zap.Int("filtered", len(filtered)))

		if len(filtered) == 0 {
			logger.Info("terminal prompt: No snapshots found matching criteria")
			return nil
		}

		// Display snapshots
		if groupBy != "" {
			displaySnapshotsGrouped(logger, filtered, groupBy, detailed)
		} else {
			displaySnapshots(logger, filtered, detailed)
		}

		return nil
	}),
}

// filterSnapshots applies filters to snapshot list
func filterSnapshots(snapshots []backup.Snapshot, filterTags []string, filterHost, filterPath string) []backup.Snapshot {
	filtered := []backup.Snapshot{}

	for _, snap := range snapshots {
		// Tag filter
		if len(filterTags) > 0 {
			hasTag := false
			for _, tag := range filterTags {
				for _, snapTag := range snap.Tags {
					if tag == snapTag {
						hasTag = true
						break
					}
				}
				if hasTag {
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		// Host filter
		if filterHost != "" && snap.Hostname != filterHost {
			continue
		}

		// Path filter
		if filterPath != "" {
			hasPath := false
			for _, path := range snap.Paths {
				if strings.Contains(path, filterPath) {
					hasPath = true
					break
				}
			}
			if !hasPath {
				continue
			}
		}

		filtered = append(filtered, snap)
	}

	return filtered
}

// displaySnapshots shows snapshots in tabular format
func displaySnapshots(logger otelzap.LoggerWithCtx, snapshots []backup.Snapshot, detailed bool) {
	logger.Info("terminal prompt: \nBackup Snapshots:")
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 140)))

	if detailed {
		// Detailed format with more information
		fmt.Printf("%-12s %-20s %-8s %-15s %-12s %-40s %s\n",
			"ID", "TIME", "AGE", "HOST", "PARENT", "PATHS", "TAGS")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 140)))

		for _, snap := range snapshots {
			id := truncateString(snap.ID, 12)
			timeStr := snap.Time.Format("2006-01-02 15:04:05")
			age := formatAge(snap.Time)
			parent := truncateString(snap.Parent, 12)
			if parent == "" {
				parent = "-"
			}

			paths := strings.Join(snap.Paths, ", ")
			paths = truncateString(paths, 40)

			tags := strings.Join(snap.Tags, ", ")

			fmt.Printf("%-12s %-20s %-8s %-15s %-12s %-40s %s\n",
				id, timeStr, age, snap.Hostname, parent, paths, tags)
		}
	} else {
		// Compact format
		fmt.Printf("%-12s %-20s %-8s %-15s %-50s %s\n",
			"ID", "TIME", "AGE", "HOST", "PATHS", "TAGS")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 140)))

		for _, snap := range snapshots {
			id := truncateString(snap.ID, 12)
			timeStr := snap.Time.Format("2006-01-02 15:04:05")
			age := formatAge(snap.Time)

			paths := strings.Join(snap.Paths, ", ")
			paths = truncateString(paths, 50)

			tags := strings.Join(snap.Tags, ", ")

			fmt.Printf("%-12s %-20s %-8s %-15s %-50s %s\n",
				id, timeStr, age, snap.Hostname, paths, tags)
		}
	}

	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 140)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Total snapshots: %d", len(snapshots))))
}

// displaySnapshotsGrouped shows snapshots grouped by a field
func displaySnapshotsGrouped(logger otelzap.LoggerWithCtx, snapshots []backup.Snapshot, groupBy string, detailed bool) {
	// Group snapshots
	groups := make(map[string][]backup.Snapshot)

	for _, snap := range snapshots {
		var key string
		switch groupBy {
		case "host", "hostname":
			key = snap.Hostname
		case "tag":
			if len(snap.Tags) > 0 {
				key = snap.Tags[0]
			} else {
				key = "(no tags)"
			}
		case "date":
			key = snap.Time.Format("2006-01-02")
		default:
			key = "all"
		}

		groups[key] = append(groups[key], snap)
	}

	// Display each group
	for groupName, groupSnapshots := range groups {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("\n%s: %s (%d snapshots)",
			strings.ToUpper(groupBy), groupName, len(groupSnapshots))))
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 140)))

		displaySnapshots(logger, groupSnapshots, detailed)
	}
}

// displayRepositoryStats shows repository statistics
func displayRepositoryStats(logger otelzap.LoggerWithCtx, stats *backup.RepositoryStats) {
	fmt.Printf("Repository: %s\n", stats.RepositoryID)
	fmt.Printf("Total Size: %s\n", humanizeBytes(stats.TotalSize))
	fmt.Printf("Total Files: %d\n", stats.TotalFileCount)
	fmt.Printf("Total Snapshots: %d\n", stats.SnapshotCount)
	fmt.Printf("Compression Ratio: %.2f%%\n", stats.CompressionRatio*100)

	if stats.LastCheck.IsZero() {
		fmt.Printf("Last Check: Never\n")
	} else {
		fmt.Printf("Last Check: %s (%s ago)\n",
			stats.LastCheck.Format("2006-01-02 15:04:05"),
			formatAge(stats.LastCheck))
	}

	if len(stats.HostStats) > 0 {
		fmt.Printf("\nPer-Host Statistics:\n")
		for host, hostStat := range stats.HostStats {
			fmt.Printf("  %s: %d snapshots, %s\n",
				host, hostStat.SnapshotCount, humanizeBytes(hostStat.Size))
		}
	}
}

// formatAge returns a human-readable age string
func formatAge(t time.Time) string {
	duration := time.Since(t)

	if duration < time.Minute {
		return "now"
	}
	if duration < time.Hour {
		minutes := int(duration.Minutes())
		return fmt.Sprintf("%dm", minutes)
	}
	if duration < 24*time.Hour {
		hours := int(duration.Hours())
		return fmt.Sprintf("%dh", hours)
	}
	if duration < 7*24*time.Hour {
		days := int(duration.Hours() / 24)
		return fmt.Sprintf("%dd", days)
	}
	if duration < 30*24*time.Hour {
		weeks := int(duration.Hours() / 24 / 7)
		return fmt.Sprintf("%dw", weeks)
	}
	if duration < 365*24*time.Hour {
		months := int(duration.Hours() / 24 / 30)
		return fmt.Sprintf("%dmo", months)
	}

	years := int(duration.Hours() / 24 / 365)
	return fmt.Sprintf("%dy", years)
}

// truncateString truncates a string to the specified length
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	if length < 3 {
		return s[:length]
	}
	return s[:length-3] + "..."
}

// humanizeBytes converts bytes to human-readable format
func humanizeBytes(bytes int64) string {
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

func init() {
	ListCmd.AddCommand(backupsCmd)

	// Repository selection
	backupsCmd.Flags().String("repo", "", "Repository to list snapshots from (uses default if not specified)")

	// Filtering options
	backupsCmd.Flags().StringSlice("tags", nil, "Filter by tags (comma-separated)")
	backupsCmd.Flags().String("host", "", "Filter by hostname")
	backupsCmd.Flags().String("path", "", "Filter by path")
	backupsCmd.Flags().Int("last", 0, "Show only the last N snapshots")

	// Display options
	backupsCmd.Flags().Bool("detailed", false, "Show detailed snapshot information")
	backupsCmd.Flags().String("group-by", "", "Group snapshots by field (host, tag, date)")
	backupsCmd.Flags().Bool("stats", false, "Show repository statistics")
}
