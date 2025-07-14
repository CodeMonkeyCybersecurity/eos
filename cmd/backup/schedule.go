// cmd/backup/schedule.go

package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup/schedule"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/systemd"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Manage automated backup schedules",
	Long: `Create and manage systemd timers for automated backups.

Examples:
  # Enable scheduled backups for a profile
  eos backup schedule enable system
  
  # Disable scheduled backups
  eos backup schedule disable system
  
  # Show schedule status
  eos backup schedule status
  
  # Run scheduled backup immediately
  eos backup schedule run system`,
}

var scheduleEnableCmd = &cobra.Command{
	Use:   "enable <profile>",
	Short: "Enable scheduled backups for a profile",
	Long: `Enable automatic backups for a profile using systemd timers.

Creates systemd service and timer files based on the profile's schedule configuration.
The profile must have a schedule configured with either cron or OnCalendar format.

Examples:
  # Enable daily backups for system profile
  eos backup schedule enable system`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		profileName := args[0]
		logger.Info("Enabling scheduled backup",
			zap.String("profile", profileName))

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

		// Check if schedule is configured
		if profile.Schedule == nil || (profile.Schedule.Cron == "" && profile.Schedule.OnCalendar == "") {
			return fmt.Errorf("profile %q has no schedule configured", profileName)
		}

		// Create systemd service file
		serviceName := fmt.Sprintf("eos-backup-%s.service", profileName)
		servicePath := filepath.Join("/etc/systemd/system", serviceName)

		serviceContent := fmt.Sprintf(`[Unit]
Description=Eos Backup - %s
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/eos backup update run %s
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, profileName, profileName)

		logger.Info("Creating systemd service",
			zap.String("path", servicePath))

		if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
			return fmt.Errorf("writing service file: %w", err)
		}

		// Create systemd timer file
		timerName := fmt.Sprintf("eos-backup-%s.timer", profileName)
		timerPath := filepath.Join("/etc/systemd/system", timerName)

		// Convert cron to OnCalendar if needed
		onCalendar := profile.Schedule.OnCalendar
		if onCalendar == "" && profile.Schedule.Cron != "" {
			onCalendar = schedule.CronToOnCalendar(rc, profile.Schedule.Cron)
		}

		timerContent := fmt.Sprintf(`[Unit]
Description=Eos Backup Timer - %s
Requires=%s

[Timer]
OnCalendar=%s
Persistent=true

[Install]
WantedBy=timers.target
`, profileName, serviceName, onCalendar)

		logger.Info("Creating systemd timer",
			zap.String("path", timerPath),
			zap.String("schedule", onCalendar))

		if err := os.WriteFile(timerPath, []byte(timerContent), 0644); err != nil {
			return fmt.Errorf("writing timer file: %w", err)
		}

		// Reload systemd and enable timer
		logger.Info("Enabling systemd timer")

		cmds := [][]string{
			{"systemctl", "daemon-reload"},
			{"systemctl", "enable", timerName},
			{"systemctl", "start", timerName},
		}

		for _, cmdArgs := range cmds {
			if err := systemd.RunSystemctl(rc, cmdArgs...); err != nil {
				return fmt.Errorf("running %s: %w", strings.Join(cmdArgs, " "), err)
			}
		}

		logger.Info("Scheduled backup enabled successfully",
			zap.String("profile", profileName),
			zap.String("timer", timerName))

		return nil
	}),
}

var scheduleDisableCmd = &cobra.Command{
	Use:   "disable <profile>",
	Short: "Disable scheduled backups for a profile",
	Long: `Disable automatic backups for a profile.

Stops and disables the systemd timer, removes service and timer files.

Examples:
  # Disable scheduled backups for system profile
  eos backup schedule disable system`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		profileName := args[0]
		logger.Info("Disabling scheduled backup",
			zap.String("profile", profileName))

		timerName := fmt.Sprintf("eos-backup-%s.timer", profileName)
		serviceName := fmt.Sprintf("eos-backup-%s.service", profileName)

		// Stop and disable timer
		cmds := [][]string{
			{"systemctl", "stop", timerName},
			{"systemctl", "disable", timerName},
		}

		for _, cmdArgs := range cmds {
			if err := systemd.RunSystemctl(rc, cmdArgs...); err != nil {
				logger.Warn("Failed to run systemctl command",
					zap.Strings("command", cmdArgs),
					zap.Error(err))
			}
		}

		// Remove service and timer files
		files := []string{
			filepath.Join("/etc/systemd/system", timerName),
			filepath.Join("/etc/systemd/system", serviceName),
		}

		for _, file := range files {
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				logger.Warn("Failed to remove file",
					zap.String("file", file),
					zap.Error(err))
			}
		}

		// Reload systemd
		if err := systemd.RunSystemctl(rc, "systemctl", "daemon-reload"); err != nil {
			logger.Warn("Failed to reload systemd",
				zap.Error(err))
		}

		logger.Info("Scheduled backup disabled successfully",
			zap.String("profile", profileName))

		return nil
	}),
}

var scheduleStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show status of all scheduled backups",
	Long: `Display the status of all backup profile schedules.

Shows profile name, schedule, systemd timer status, and next run time.

Examples:
  # Show status of all scheduled backups
  eos backup schedule status`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Checking backup schedule status")

		// Load configuration to get profiles
		config, err := backup.LoadConfig(rc)
		if err != nil {
			return fmt.Errorf("loading configuration: %w", err)
		}

		logger.Info("terminal prompt: \nBackup Schedule Status:")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 80)))
		fmt.Printf("%-20s %-20s %-20s %s\n", "PROFILE", "SCHEDULE", "TIMER STATUS", "NEXT RUN")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 80)))

		for profileName, profile := range config.Profiles {
			schedule := "-"
			if profile.Schedule != nil {
				if profile.Schedule.Cron != "" {
					schedule = profile.Schedule.Cron
				} else if profile.Schedule.OnCalendar != "" {
					schedule = profile.Schedule.OnCalendar
				}
			}

			// timerName := fmt.Sprintf("eos-backup-%s.timer", profileName)
			status := "Not scheduled"
			nextRun := "-"

			// Check systemd timer status
			timerName := fmt.Sprintf("eos-backup-%s.timer", profileName)
			if timerStatus, nextRunTime, err := systemd.GetTimerStatus(rc, timerName); err != nil {
				logger.Debug("Failed to get timer status",
					zap.String("timer", timerName),
					zap.Error(err))
			} else {
				status = timerStatus
				nextRun = nextRunTime
			}

			fmt.Printf("%-20s %-20s %-20s %s\n",
				profileName, schedule, status, nextRun)
		}
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", )))

		return nil
	}),
}

var scheduleRunCmd = &cobra.Command{
	Use:   "run <profile>",
	Short: "Run a scheduled backup immediately",
	Long: `Manually trigger a scheduled backup service.

Starts the systemd service associated with the profile immediately,
without waiting for the next scheduled run.

Examples:
  # Run system backup immediately
  eos backup schedule run system`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		profileName := args[0]
		logger.Info("Running scheduled backup immediately",
			zap.String("profile", profileName))

		serviceName := fmt.Sprintf("eos-backup-%s.service", profileName)

		// Start the service
		if err := systemd.RunSystemctl(rc, "systemctl", "start", serviceName); err != nil {
			return fmt.Errorf("starting backup service: %w", err)
		}

		logger.Info("Backup service started",
			zap.String("service", serviceName))

		// Show service status
		logger.Info("terminal prompt: Started service", zap.String("service", serviceName))
		logger.Info("terminal prompt: Use 'journalctl -u " + serviceName + " -f' to follow the backup progress")

		return nil
	}),
}

func init() {
	scheduleCmd.AddCommand(scheduleEnableCmd)
	scheduleCmd.AddCommand(scheduleDisableCmd)
	scheduleCmd.AddCommand(scheduleStatusCmd)
	scheduleCmd.AddCommand(scheduleRunCmd)
}

// Helper functions have been migrated to:
// - pkg/backup/schedule/converter.go (cronToOnCalendar)
// - pkg/systemd/systemctl.go (runSystemctl)
