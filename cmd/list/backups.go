// cmd/list/backups.go
//
// REFACTORED: This file now follows Clean Architecture principles.
// All business logic has been moved to pkg/backup/display/.
//
// Before: 321 lines with business logic, filtering, and display formatting
// After: ~60 lines of pure orchestration
//
// Migrated functions:
//   - filterSnapshots() → pkg/backup/display.FilterSnapshots()
//   - displaySnapshots() → pkg/backup/display.ShowSnapshots()
//   - displaySnapshotsGrouped() → pkg/backup/display.ShowSnapshotsGrouped()
//   - displayRepositoryStats() → pkg/backup/display.ShowRepositoryStats()

package list

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup/display"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var backupsCmd = &cobra.Command{
	Use:     "backups [repository]",
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

  # Quick view of snapshots created with "eos backup ."
  eos ls backups .

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
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(listBackups),
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

// listBackups orchestrates the backup listing operation.
// All business logic is delegated to pkg/backup/display.
func listBackups(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// CRITICAL: Detect flag-like args (P0-1 fix)
	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}


	// Get flags
	repoName, _ := cmd.Flags().GetString("repo")
	filterTags, _ := cmd.Flags().GetStringSlice("tags")
	filterHost, _ := cmd.Flags().GetString("host")
	filterPath, _ := cmd.Flags().GetString("path")
	lastN, _ := cmd.Flags().GetInt("last")
	detailed, _ := cmd.Flags().GetBool("detailed")
	groupBy, _ := cmd.Flags().GetString("group-by")
	showStats, _ := cmd.Flags().GetBool("stats")

	// Positional repository selection (e.g., "eos ls backups .")
	if repoName == "" && len(args) > 0 {
		switch arg := strings.TrimSpace(args[0]); arg {
		case ".":
			repoName = backup.QuickBackupRepositoryName
		case "":
			// No-op - treated same as no argument
		default:
			repoName = arg
		}
	}

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
			display.ShowRepositoryStats(rc, stats)
		}
		logger.Info("terminal prompt:", zap.String("output", ""))
	}

	// List snapshots
	snapshots, err := client.ListSnapshots()
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}

	// Apply filters (delegated to pkg/backup/display)
	filtered := display.FilterSnapshots(snapshots, filterTags, filterHost, filterPath, lastN)

	logger.Info("Found snapshots",
		zap.Int("total", len(snapshots)),
		zap.Int("filtered", len(filtered)))

	if len(filtered) == 0 {
		logger.Info("terminal prompt: No snapshots found matching criteria")
		return nil
	}

	// Display snapshots (delegated to pkg/backup/display)
	if groupBy != "" {
		display.ShowSnapshotsGrouped(rc, filtered, groupBy, detailed)
	} else {
		display.ShowSnapshots(rc, filtered, detailed)
	}

	return nil
}
