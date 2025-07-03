// cmd/backup/update.go

package backup

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update backup resources (run backups, modify configs)",
}

var updateRunCmd = &cobra.Command{
	Use:   "run <profile>",
	Short: "Run a backup using the specified profile",
	Long: `Execute a backup using a configured profile.

Examples:
  # Run system backup
  eos backup update run system
  
  # Run with specific tags
  eos backup update run home --tags "manual,important"
  
  # Run with custom host
  eos backup update run system --host prod-server`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(runBackup),
}

var updateConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Update backup configuration",
	Long: `Update global backup configuration settings.

Examples:
  # Set default repository
  eos backup update config --default-repo remote
  
  # Update check interval
  eos backup update config --check-interval weekly
  
  # Configure notifications
  eos backup update config --notify-failure --notify-method email --notify-target ops@example.com`,
	RunE: eos.Wrap(updateConfig),
}

var updateProfileCmd = &cobra.Command{
	Use:   "profile <name>",
	Short: "Update an existing backup profile",
	Args:  cobra.ExactArgs(1),
	RunE:  eos.Wrap(updateProfile),
}

func init() {
	updateCmd.AddCommand(updateRunCmd)
	updateCmd.AddCommand(updateConfigCmd)
	updateCmd.AddCommand(updateProfileCmd)

	// Run flags
	updateRunCmd.Flags().StringSlice("tags", nil, "Additional tags for this backup")
	updateRunCmd.Flags().String("host", "", "Override hostname for this backup")
	updateRunCmd.Flags().Bool("dry-run", false, "Show what would be backed up without doing it")

	// Config flags
	updateConfigCmd.Flags().String("default-repo", "", "Set default repository")
	updateConfigCmd.Flags().String("check-interval", "", "Repository check interval")
	updateConfigCmd.Flags().Int("parallelism", 0, "Parallel operations")
	updateConfigCmd.Flags().Bool("notify-success", false, "Send notifications on success")
	updateConfigCmd.Flags().Bool("notify-failure", false, "Send notifications on failure")
	updateConfigCmd.Flags().String("notify-method", "", "Notification method (email, slack, webhook)")
	updateConfigCmd.Flags().String("notify-target", "", "Notification target")

	// Profile update flags
	updateProfileCmd.Flags().StringSlice("add-paths", nil, "Add paths to profile")
	updateProfileCmd.Flags().StringSlice("remove-paths", nil, "Remove paths from profile")
	updateProfileCmd.Flags().StringSlice("add-excludes", nil, "Add exclude patterns")
	updateProfileCmd.Flags().StringSlice("remove-excludes", nil, "Remove exclude patterns")
	updateProfileCmd.Flags().String("schedule", "", "Update schedule")
	updateProfileCmd.Flags().Bool("clear-schedule", false, "Remove schedule")
}

func runBackup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	profileName := args[0]
	extraTags, _ := cmd.Flags().GetStringSlice("tags")
	hostOverride, _ := cmd.Flags().GetString("host")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	logger.Info("Starting backup run",
		zap.String("profile", profileName),
		zap.Bool("dry_run", dryRun))

	// Load configuration
	config, err := backup.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Get profile
	profile, exists := config.Profiles[profileName]
	if !exists {
		return fmt.Errorf("profile %q not found", profileName)
	}

	// Apply overrides
	if len(extraTags) > 0 {
		profile.Tags = append(profile.Tags, extraTags...)
	}
	if hostOverride != "" {
		profile.Host = hostOverride
	}

	// Determine repository
	repoName := profile.Repository
	if repoName == "" {
		repoName = config.DefaultRepository
		if repoName == "" {
			return fmt.Errorf("no repository specified and no default configured")
		}
	}

	logger.Info("Using repository",
		zap.String("repository", repoName),
		zap.Strings("paths", profile.Paths),
		zap.Strings("tags", profile.Tags))

	// Create backup client
	client, err := backup.NewClient(rc, repoName)
	if err != nil {
		return fmt.Errorf("creating backup client: %w", err)
	}

	// Run pre-backup hooks using the modular helper
	if profile.Hooks != nil && len(profile.Hooks.PreBackup) > 0 {
		logger.Info("Running pre-backup hooks")
		for _, hook := range profile.Hooks.PreBackup {
			if err := backup.RunHook(rc.Ctx, logger, hook); err != nil {
				logger.Error("Pre-backup hook failed",
					zap.String("hook", hook),
					zap.Error(err))
				if profile.Hooks.OnError != nil {
					for _, errorHook := range profile.Hooks.OnError {
						_ = backup.RunHook(rc.Ctx, logger, errorHook)
					}
				}
				return fmt.Errorf("pre-backup hook failed: %w", err)
			}
		}
	}

	// Perform backup using AIE pattern
	backupOp := &backup.BackupOperation{
		Client:      client,
		ProfileName: profileName,
		Profile:     profile,
		RepoName:    repoName,
		DryRun:      dryRun,
		Logger:      logger,
	}

	executor := patterns.NewExecutor(logger)
	if err := executor.Execute(rc.Ctx, backupOp, "backup_profile"); err != nil {
		// Run error hooks
		if profile.Hooks != nil && profile.Hooks.OnError != nil {
			for _, hook := range profile.Hooks.OnError {
				_ = backup.RunHook(rc.Ctx, logger, hook)
			}
		}
		return err
	}

	// Run post-backup hooks
	if profile.Hooks != nil && len(profile.Hooks.PostBackup) > 0 {
		logger.Info("Running post-backup hooks")
		for _, hook := range profile.Hooks.PostBackup {
			if err := backup.RunHook(rc.Ctx, logger, hook); err != nil {
				logger.Warn("Post-backup hook failed",
					zap.String("hook", hook),
					zap.Error(err))
			}
		}
	}

	// Send notifications if configured
	if config.Settings.Notifications.OnSuccess {
		if err := backup.SendNotification(rc.Ctx, logger, config.Settings.Notifications, 
			"Backup completed successfully", profileName); err != nil {
			logger.Warn("Failed to send notification", zap.Error(err))
		}
	}

	logger.Info("Backup completed successfully",
		zap.String("profile", profileName))

	return nil
}

func updateConfig(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Updating backup configuration")

	// Load existing config
	config, err := backup.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Update settings based on flags
	if defaultRepo, _ := cmd.Flags().GetString("default-repo"); defaultRepo != "" {
		if _, exists := config.Repositories[defaultRepo]; !exists {
			return fmt.Errorf("repository %q not found", defaultRepo)
		}
		config.DefaultRepository = defaultRepo
		logger.Info("Updated default repository",
			zap.String("repository", defaultRepo))
	}

	if checkInterval, _ := cmd.Flags().GetString("check-interval"); checkInterval != "" {
		config.Settings.CheckInterval = checkInterval
		logger.Info("Updated check interval",
			zap.String("interval", checkInterval))
	}

	if parallelism, _ := cmd.Flags().GetInt("parallelism"); parallelism > 0 {
		config.Settings.Parallelism = parallelism
		logger.Info("Updated parallelism",
			zap.Int("parallelism", parallelism))
	}

	// Update notification settings
	if cmd.Flags().Changed("notify-success") {
		notifySuccess, _ := cmd.Flags().GetBool("notify-success")
		config.Settings.Notifications.OnSuccess = notifySuccess
	}

	if cmd.Flags().Changed("notify-failure") {
		notifyFailure, _ := cmd.Flags().GetBool("notify-failure")
		config.Settings.Notifications.OnFailure = notifyFailure
	}

	if method, _ := cmd.Flags().GetString("notify-method"); method != "" {
		config.Settings.Notifications.Method = method
	}

	if target, _ := cmd.Flags().GetString("notify-target"); target != "" {
		config.Settings.Notifications.Target = target
	}

	// Save updated configuration
	if err := backup.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Configuration updated successfully")
	return nil
}

func updateProfile(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	profileName := args[0]
	logger.Info("Updating backup profile",
		zap.String("profile", profileName))

	// Load configuration
	config, err := backup.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Get existing profile
	profile, exists := config.Profiles[profileName]
	if !exists {
		return fmt.Errorf("profile %q not found", profileName)
	}

	// Update paths
	if addPaths, _ := cmd.Flags().GetStringSlice("add-paths"); len(addPaths) > 0 {
		profile.Paths = append(profile.Paths, addPaths...)
		logger.Info("Added paths to profile",
			zap.Strings("paths", addPaths))
	}

	if removePaths, _ := cmd.Flags().GetStringSlice("remove-paths"); len(removePaths) > 0 {
		newPaths := []string{}
		for _, path := range profile.Paths {
			remove := false
			for _, rPath := range removePaths {
				if path == rPath {
					remove = true
					break
				}
			}
			if !remove {
				newPaths = append(newPaths, path)
			}
		}
		profile.Paths = newPaths
		logger.Info("Removed paths from profile",
			zap.Strings("paths", removePaths))
	}

	// Update excludes
	if addExcludes, _ := cmd.Flags().GetStringSlice("add-excludes"); len(addExcludes) > 0 {
		profile.Excludes = append(profile.Excludes, addExcludes...)
		logger.Info("Added excludes to profile",
			zap.Strings("excludes", addExcludes))
	}

	if removeExcludes, _ := cmd.Flags().GetStringSlice("remove-excludes"); len(removeExcludes) > 0 {
		newExcludes := []string{}
		for _, exclude := range profile.Excludes {
			remove := false
			for _, rExclude := range removeExcludes {
				if exclude == rExclude {
					remove = true
					break
				}
			}
			if !remove {
				newExcludes = append(newExcludes, exclude)
			}
		}
		profile.Excludes = newExcludes
		logger.Info("Removed excludes from profile",
			zap.Strings("excludes", removeExcludes))
	}

	// Update schedule
	if schedule, _ := cmd.Flags().GetString("schedule"); schedule != "" {
		if profile.Schedule == nil {
			profile.Schedule = &backup.Schedule{}
		}
		profile.Schedule.Cron = schedule
		logger.Info("Updated schedule",
			zap.String("schedule", schedule))
	}

	if clearSchedule, _ := cmd.Flags().GetBool("clear-schedule"); clearSchedule {
		profile.Schedule = nil
		logger.Info("Cleared schedule")
	}

	// Save updated profile
	config.Profiles[profileName] = profile
	if err := backup.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logger.Info("Profile updated successfully")
	return nil
}

