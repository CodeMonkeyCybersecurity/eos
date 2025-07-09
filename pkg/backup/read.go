package backup

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func ReadRepository(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	repoName := args[0]
	logger.Info("Reading repository information",
		zap.String("repository", repoName))

	config, err := LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	repo, exists := config.Repositories[repoName]
	if !exists {
		return fmt.Errorf("repository %q not found", repoName)
	}

	// Display repository details
	fmt.Printf("\nRepository: %s\n", repo.Name)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Backend:     %s\n", repo.Backend)
	fmt.Printf("URL:         %s\n", repo.URL)

	if repo.Name == config.DefaultRepository {
		fmt.Printf("Default:     Yes\n")
	}

	if len(repo.Environment) > 0 {
		fmt.Printf("\nEnvironment Variables:\n")
		for k, v := range repo.Environment {
			// Mask sensitive values
			displayValue := v
			if strings.Contains(strings.ToLower(k), "key") ||
				strings.Contains(strings.ToLower(k), "secret") ||
				strings.Contains(strings.ToLower(k), "password") {
				displayValue = "***"
			}
			fmt.Printf("  %s: %s\n", k, displayValue)
		}
	}

	// Check repository stats if possible
	client, err := NewClient(rc, repoName)
	if err == nil {
		snapshots, err := client.ListSnapshots()
		if err == nil {
			fmt.Printf("\nRepository Statistics:\n")
			fmt.Printf("  Total Snapshots: %d\n", len(snapshots))

			if len(snapshots) > 0 {
				// Find oldest and newest
				oldest := snapshots[0].Time
				newest := snapshots[0].Time

				for _, snap := range snapshots {
					if snap.Time.Before(oldest) {
						oldest = snap.Time
					}
					if snap.Time.After(newest) {
						newest = snap.Time
					}
				}

				fmt.Printf("  Oldest Snapshot: %s\n", oldest.Format("2006-01-02 15:04:05"))
				fmt.Printf("  Newest Snapshot: %s\n", newest.Format("2006-01-02 15:04:05"))
			}
		}
	}

	fmt.Println()
	return nil
}

func ReadProfile(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	profileName := args[0]
	logger.Info("Reading profile information",
		zap.String("profile", profileName))

	config, err := LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	profile, exists := config.Profiles[profileName]
	if !exists {
		return fmt.Errorf("profile %q not found", profileName)
	}

	// Display profile details
	fmt.Printf("\nProfile: %s\n", profile.Name)
	fmt.Println(strings.Repeat("-", 60))

	if profile.Description != "" {
		fmt.Printf("Description: %s\n", profile.Description)
	}

	fmt.Printf("Repository:  %s\n", profile.Repository)

	fmt.Printf("\nPaths:\n")
	for _, path := range profile.Paths {
		fmt.Printf("  - %s\n", path)
	}

	if len(profile.Excludes) > 0 {
		fmt.Printf("\nExcludes:\n")
		for _, exclude := range profile.Excludes {
			fmt.Printf("  - %s\n", exclude)
		}
	}

	if len(profile.Tags) > 0 {
		fmt.Printf("\nTags: %s\n", strings.Join(profile.Tags, ", "))
	}

	if profile.Host != "" {
		fmt.Printf("Host Override: %s\n", profile.Host)
	}

	if profile.Schedule != nil {
		fmt.Printf("\nSchedule:\n")
		if profile.Schedule.Cron != "" {
			fmt.Printf("  Cron: %s\n", profile.Schedule.Cron)
		}
		if profile.Schedule.OnCalendar != "" {
			fmt.Printf("  OnCalendar: %s\n", profile.Schedule.OnCalendar)
		}
	}

	if profile.Retention != nil {
		fmt.Printf("\nRetention Policy:\n")
		if profile.Retention.KeepLast > 0 {
			fmt.Printf("  Keep Last:    %d\n", profile.Retention.KeepLast)
		}
		if profile.Retention.KeepDaily > 0 {
			fmt.Printf("  Keep Daily:   %d\n", profile.Retention.KeepDaily)
		}
		if profile.Retention.KeepWeekly > 0 {
			fmt.Printf("  Keep Weekly:  %d\n", profile.Retention.KeepWeekly)
		}
		if profile.Retention.KeepMonthly > 0 {
			fmt.Printf("  Keep Monthly: %d\n", profile.Retention.KeepMonthly)
		}
		if profile.Retention.KeepYearly > 0 {
			fmt.Printf("  Keep Yearly:  %d\n", profile.Retention.KeepYearly)
		}
	}

	if profile.Hooks != nil {
		if len(profile.Hooks.PreBackup) > 0 {
			fmt.Printf("\nPre-Backup Hooks:\n")
			for _, hook := range profile.Hooks.PreBackup {
				fmt.Printf("  - %s\n", hook)
			}
		}
		if len(profile.Hooks.PostBackup) > 0 {
			fmt.Printf("\nPost-Backup Hooks:\n")
			for _, hook := range profile.Hooks.PostBackup {
				fmt.Printf("  - %s\n", hook)
			}
		}
		if len(profile.Hooks.OnError) > 0 {
			fmt.Printf("\nError Hooks:\n")
			for _, hook := range profile.Hooks.OnError {
				fmt.Printf("  - %s\n", hook)
			}
		}
	}

	fmt.Println()
	return nil
}

func ReadSnapshot(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	snapshotID := args[0]
	repoName, _ := cmd.Flags().GetString("repo")

	// Use default repository if not specified
	if repoName == "" {
		config, err := LoadConfig(rc)
		if err != nil {
			return fmt.Errorf("loading configuration: %w", err)
		}
		repoName = config.DefaultRepository
		if repoName == "" {
			return fmt.Errorf("no repository specified and no default configured")
		}
	}

	logger.Info("Reading snapshot information",
		zap.String("snapshot", snapshotID),
		zap.String("repository", repoName))

	// TODO: Implement detailed snapshot information retrieval
	fmt.Printf("\nSnapshot: %s\n", snapshotID)
	fmt.Println("(Detailed snapshot information not yet implemented)")

	return nil
}
