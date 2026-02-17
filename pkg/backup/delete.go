// pkg/backup/delete.go

package backup

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func DeleteSnapshot(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	snapshotID := args[0]
	repoName, _ := cmd.Flags().GetString("repo")
	force, _ := cmd.Flags().GetBool("force")

	resolvedRepoName, err := ResolveRepositoryName(rc, repoName)
	if err != nil {
		return err
	}
	repoName = resolvedRepoName

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
	client, err := NewClient(rc, repoName)
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

func DeleteProfile(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	profileName := args[0]
	force, _ := cmd.Flags().GetBool("force")

	logger.Info("Deleting backup profile",
		zap.String("profile", profileName),
		zap.Bool("force", force))

	// Load configuration
	config, err := LoadConfig(rc)
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
	if err := SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Profile deleted successfully")
	return nil
}

func PruneSnapshots(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	repoName, _ := cmd.Flags().GetString("repo")
	profileName, _ := cmd.Flags().GetString("profile")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	logger.Info("Pruning snapshots",
		zap.String("repository", repoName),
		zap.String("profile", profileName),
		zap.Bool("dry_run", dryRun))

	// Load configuration
	config, err := LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Determine retention policy
	var retention *Retention

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
			retention = &Retention{
				KeepLast:    keepLast,
				KeepDaily:   keepDaily,
				KeepWeekly:  keepWeekly,
				KeepMonthly: keepMonthly,
				KeepYearly:  keepYearly,
			}
		}
	}

	resolvedRepoName, err := ResolveRepositoryNameFromConfig(config, repoName)
	if err != nil {
		return err
	}
	repoName = resolvedRepoName

	// Create backup client
	client, err := NewClient(rc, repoName)
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
