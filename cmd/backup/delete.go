// cmd/backup/delete.go

package backup

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete backup resources",
}

var deleteSnapshotCmd = &cobra.Command{
	Use:   "snapshot <id>",
	Short: "Delete a specific snapshot",
	Args:  cobra.ExactArgs(1),
	RunE:  eos.Wrap(deleteSnapshot),
}

var deleteProfileCmd = &cobra.Command{
	Use:   "profile <name>",
	Short: "Delete a backup profile",
	Args:  cobra.ExactArgs(1),
	RunE:  eos.Wrap(deleteProfile),
}

var pruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Prune old snapshots according to retention policy",
	Long: `Remove old snapshots based on retention policies.

Examples:
  # Prune using profile's retention policy
  eos backup delete prune --profile system
  
  # Prune with custom retention
  eos backup delete prune --repo remote --keep-last 5 --keep-daily 7
  
  # Dry run to see what would be deleted
  eos backup delete prune --profile system --dry-run`,
	RunE: eos.Wrap(pruneSnapshots),
}

func init() {
	deleteCmd.AddCommand(deleteSnapshotCmd)
	deleteCmd.AddCommand(deleteProfileCmd)
	deleteCmd.AddCommand(pruneCmd)

	// Delete snapshot flags
	deleteSnapshotCmd.Flags().String("repo", "", "Repository containing the snapshot")
	deleteSnapshotCmd.Flags().Bool("force", false, "Force deletion without confirmation")

	// Delete profile flags
	deleteProfileCmd.Flags().Bool("force", false, "Force deletion without confirmation")

	// Prune flags
	pruneCmd.Flags().String("repo", "", "Repository to prune")
	pruneCmd.Flags().String("profile", "", "Use retention policy from profile")
	pruneCmd.Flags().Int("keep-last", 0, "Keep last N snapshots")
	pruneCmd.Flags().Int("keep-daily", 0, "Keep N daily snapshots")
	pruneCmd.Flags().Int("keep-weekly", 0, "Keep N weekly snapshots")
	pruneCmd.Flags().Int("keep-monthly", 0, "Keep N monthly snapshots")
	pruneCmd.Flags().Int("keep-yearly", 0, "Keep N yearly snapshots")
	pruneCmd.Flags().Bool("dry-run", false, "Show what would be deleted without doing it")
}

func deleteSnapshot(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	snapshotID := args[0]
	repoName, _ := cmd.Flags().GetString("repo")
	force, _ := cmd.Flags().GetBool("force")

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

	logger.Info("Deleting snapshot",
		zap.String("snapshot", snapshotID),
		zap.String("repository", repoName),
		zap.Bool("force", force))

	// TODO: Add confirmation prompt if not force
	if !force {
		logger.Warn("Snapshot deletion requires --force flag for safety")
		return fmt.Errorf("use --force to confirm snapshot deletion")
	}

	// Create backup client
	client, err := backup.NewClient(rc, repoName)
	if err != nil {
		return fmt.Errorf("creating backup client: %w", err)
	}

	// Delete snapshot
	if _, err := client.RunRestic("forget", snapshotID); err != nil {
		return fmt.Errorf("deleting snapshot: %w", err)
	}

	logger.Info("Snapshot deleted successfully")
	return nil
}

func deleteProfile(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	profileName := args[0]
	force, _ := cmd.Flags().GetBool("force")

	logger.Info("Deleting backup profile",
		zap.String("profile", profileName),
		zap.Bool("force", force))

	// Load configuration
	config, err := backup.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Check if profile exists
	if _, exists := config.Profiles[profileName]; !exists {
		return fmt.Errorf("profile %q not found", profileName)
	}

	// TODO: Add confirmation prompt if not force
	if !force {
		logger.Warn("Profile deletion requires --force flag for safety")
		return fmt.Errorf("use --force to confirm profile deletion")
	}

	// Delete profile
	delete(config.Profiles, profileName)

	// Save configuration
	if err := backup.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Profile deleted successfully")
	return nil
}

func pruneSnapshots(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	repoName, _ := cmd.Flags().GetString("repo")
	profileName, _ := cmd.Flags().GetString("profile")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	logger.Info("Pruning snapshots",
		zap.String("repository", repoName),
		zap.String("profile", profileName),
		zap.Bool("dry_run", dryRun))

	// Load configuration
	config, err := backup.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Determine retention policy
	var retention *backup.Retention

	if profileName != "" {
		// Use profile's retention policy
		profile, exists := config.Profiles[profileName]
		if !exists {
			return fmt.Errorf("profile %q not found", profileName)
		}
		retention = profile.Retention
		
		// Use profile's repository if not specified
		if repoName == "" {
			repoName = profile.Repository
		}
	} else {
		// Build retention from flags
		keepLast, _ := cmd.Flags().GetInt("keep-last")
		keepDaily, _ := cmd.Flags().GetInt("keep-daily")
		keepWeekly, _ := cmd.Flags().GetInt("keep-weekly")
		keepMonthly, _ := cmd.Flags().GetInt("keep-monthly")
		keepYearly, _ := cmd.Flags().GetInt("keep-yearly")

		if keepLast == 0 && keepDaily == 0 && keepWeekly == 0 && 
		   keepMonthly == 0 && keepYearly == 0 {
			// Use default retention
			retention = config.Settings.DefaultRetention
			if retention == nil {
				return fmt.Errorf("no retention policy specified")
			}
		} else {
			retention = &backup.Retention{
				KeepLast:    keepLast,
				KeepDaily:   keepDaily,
				KeepWeekly:  keepWeekly,
				KeepMonthly: keepMonthly,
				KeepYearly:  keepYearly,
			}
		}
	}

	// Use default repository if not specified
	if repoName == "" {
		repoName = config.DefaultRepository
		if repoName == "" {
			return fmt.Errorf("no repository specified and no default configured")
		}
	}

	// Create backup client
	client, err := backup.NewClient(rc, repoName)
	if err != nil {
		return fmt.Errorf("creating backup client: %w", err)
	}

	// Build prune command
	args = []string{"forget"}
	
	if !dryRun {
		args = append(args, "--prune")
	} else {
		args = append(args, "--dry-run")
	}

	if retention.KeepLast > 0 {
		args = append(args, "--keep-last", fmt.Sprintf("%d", retention.KeepLast))
	}
	if retention.KeepDaily > 0 {
		args = append(args, "--keep-daily", fmt.Sprintf("%d", retention.KeepDaily))
	}
	if retention.KeepWeekly > 0 {
		args = append(args, "--keep-weekly", fmt.Sprintf("%d", retention.KeepWeekly))
	}
	if retention.KeepMonthly > 0 {
		args = append(args, "--keep-monthly", fmt.Sprintf("%d", retention.KeepMonthly))
	}
	if retention.KeepYearly > 0 {
		args = append(args, "--keep-yearly", fmt.Sprintf("%d", retention.KeepYearly))
	}

	logger.Info("Applying retention policy",
		zap.Any("retention", retention),
		zap.Bool("dry_run", dryRun))

	// Run prune
	output, err := client.RunRestic(args...)
	if err != nil {
		return fmt.Errorf("pruning snapshots: %w", err)
	}

	// Display output
	fmt.Println(string(output))

	if dryRun {
		logger.Info("Dry run completed - no snapshots were deleted")
	} else {
		logger.Info("Pruning completed successfully")
	}

	return nil
}