// cmd/backup/list.go

package backup

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List backup resources",
}

var listReposCmd = &cobra.Command{
	Use:   "repositories",
	Short: "List configured backup repositories",
	Long: `List all configured backup repositories with their backends and URLs.

Shows repository name, backend type, URL, and indicates the default repository.

Examples:
  # List all repositories
  eos backup list repositories`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Listing backup repositories")

		config, err := backup.LoadConfig(rc)
		if err != nil {
			return fmt.Errorf("loading configuration: %w", err)
		}

		if len(config.Repositories) == 0 {
			logger.Info("No repositories configured")
			return nil
		}

		logger.Info("Configured repositories",
			zap.Int("count", len(config.Repositories)))

		// Display repositories
		logger.Info("terminal prompt: \nConfigured Repositories:")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 80)))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-10s %-40s", "NAME", "BACKEND", "URL")))
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 80)))

		for name, repo := range config.Repositories {
			isDefault := ""
			if name == config.DefaultRepository {
				isDefault = " (default)"
			}
			logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-10s %-40s%s",
				name, repo.Backend, repo.URL, isDefault)))
		}
		logger.Info("terminal prompt:", zap.String("output", "operation completed"))

		return nil
	}),
}

var listProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "List configured backup profiles",
	Long: `List all configured backup profiles with their settings.

Shows profile name, repository, paths, schedule, and retention policies.

Examples:
  # List all profiles
  eos backup list profiles`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Listing backup profiles")

		config, err := backup.LoadConfig(rc)
		if err != nil {
			return fmt.Errorf("loading configuration: %w", err)
		}

		if len(config.Profiles) == 0 {
			logger.Info("No profiles configured")
			return nil
		}

		logger.Info("Configured profiles",
			zap.Int("count", len(config.Profiles)))

		// Display profiles
		logger.Info("terminal prompt: \nConfigured Profiles:")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 100)))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-15s %-30s %-20s %s",
			"NAME", "REPOSITORY", "PATHS", "SCHEDULE", "RETENTION")))
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 100)))

		for name, profile := range config.Profiles {
			paths := strings.Join(profile.Paths, ", ")
			if len(paths) > 30 {
				paths = paths[:27] + "..."
			}

			schedule := "-"
			if profile.Schedule != nil && profile.Schedule.Cron != "" {
				schedule = profile.Schedule.Cron
			}

			retention := "-"
			if profile.Retention != nil {
				parts := []string{}
				if profile.Retention.KeepLast > 0 {
					parts = append(parts, fmt.Sprintf("L:%d", profile.Retention.KeepLast))
				}
				if profile.Retention.KeepDaily > 0 {
					parts = append(parts, fmt.Sprintf("D:%d", profile.Retention.KeepDaily))
				}
				if profile.Retention.KeepWeekly > 0 {
					parts = append(parts, fmt.Sprintf("W:%d", profile.Retention.KeepWeekly))
				}
				if profile.Retention.KeepMonthly > 0 {
					parts = append(parts, fmt.Sprintf("M:%d", profile.Retention.KeepMonthly))
				}
				retention = strings.Join(parts, " ")
			}

			logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-15s %-30s %-20s %s",
				name, profile.Repository, paths, schedule, retention)))
		}
		logger.Info("terminal prompt:", zap.String("output", "operation completed"))

		return nil
	}),
}

var listSnapshotsCmd = &cobra.Command{
	Use:   "snapshots",
	Short: "List snapshots in a repository",
	Long: `List all snapshots in the specified repository.

Shows snapshot ID, timestamp, hostname, paths, and tags. Supports filtering by
repository, tags, hostname, and paths.

Examples:
  # List snapshots in default repository
  eos backup list snapshots
  
  # List snapshots in specific repository
  eos backup list snapshots --repo remote
  
  # List snapshots with specific tags
  eos backup list snapshots --tags system,daily
  
  # Filter by hostname
  eos backup list snapshots --host server01`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		repoName, _ := cmd.Flags().GetString("repo")
		filterTags, _ := cmd.Flags().GetStringSlice("tags")
		filterHost, _ := cmd.Flags().GetString("host")
		filterPath, _ := cmd.Flags().GetString("path")

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

		logger.Info("Listing snapshots",
			zap.String("repository", repoName),
			zap.Strings("filter_tags", filterTags),
			zap.String("filter_host", filterHost))

		// Create backup client
		client, err := backup.NewClient(rc, repoName)
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}

		// List snapshots
		snapshots, err := client.ListSnapshots()
		if err != nil {
			return fmt.Errorf("listing snapshots: %w", err)
		}

		// Apply filters
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

		logger.Info("Found snapshots",
			zap.Int("total", len(snapshots)),
			zap.Int("filtered", len(filtered)))

		if len(filtered) == 0 {
			logger.Info("terminal prompt: No snapshots found matching criteria")
			return nil
		}

		// Display snapshots
		logger.Info("terminal prompt: \nSnapshots:")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-16s %-20s %-15s %-40s %s",
			"ID", "TIME", "HOST", "PATHS", "TAGS")))
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))

		for _, snap := range filtered {
			id := snap.ID
			if len(id) > 16 {
				id = id[:16]
			}

			timeStr := snap.Time.Format("2006-01-02 15:04:05")

			paths := strings.Join(snap.Paths, ", ")
			if len(paths) > 40 {
				paths = paths[:37] + "..."
			}

			tags := strings.Join(snap.Tags, ", ")

			logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-16s %-20s %-15s %-40s %s",
				id, timeStr, snap.Hostname, paths, tags)))
		}
		logger.Info("terminal prompt:", zap.String("output", "operation completed"))

		return nil
	}),
}

func init() {
	listCmd.AddCommand(listReposCmd)
	listCmd.AddCommand(listProfilesCmd)
	listCmd.AddCommand(listSnapshotsCmd)

	// Snapshot list flags
	listSnapshotsCmd.Flags().String("repo", "", "Repository to list snapshots from")
	listSnapshotsCmd.Flags().StringSlice("tags", nil, "Filter by tags")
	listSnapshotsCmd.Flags().String("host", "", "Filter by hostname")
	listSnapshotsCmd.Flags().String("path", "", "Filter by path")
}
