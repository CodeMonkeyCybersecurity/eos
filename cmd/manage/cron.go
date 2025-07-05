package manage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/cron_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewCronCmd creates the cron management command
func NewCronCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cron",
		Aliases: []string{"crontab", "schedule"},
		Short:   "Manage crontab entries and scheduled jobs",
		Long: `Manage crontab entries and scheduled jobs for system automation.

This command provides comprehensive cron job management including adding, removing,
listing, and validating cron expressions. Supports backup creation and dry-run modes.

Examples:
  eos manage cron list                    # List all cron jobs
  eos manage cron add "0 2 * * *" "/backup.sh"  # Add daily backup at 2 AM
  eos manage cron remove job-id           # Remove specific job by ID
  eos manage cron clear                   # Remove all cron jobs
  eos manage cron validate "0 */4 * * *"  # Validate cron expression`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			otelzap.Ctx(rc.Ctx).Info("No subcommand provided for cron command")
			_ = cmd.Help()
			return nil
		}),
	}

	// Add subcommands
	cmd.AddCommand(newCronListCmd())
	cmd.AddCommand(newCronAddCmd())
	cmd.AddCommand(newCronRemoveCmd())
	cmd.AddCommand(newCronClearCmd())
	cmd.AddCommand(newCronValidateCmd())

	return cmd
}

// newCronListCmd creates the list subcommand
func newCronListCmd() *cobra.Command {
	var (
		outputJSON bool
		user       string
	)

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "show"},
		Short:   "List all cron jobs",
		Long:    `List all cron jobs for the current or specified user.`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Listing cron jobs", zap.String("user", user))

			config := cron_management.DefaultCronConfig()
			config.User = user

			manager := cron_management.NewCronManager(config)
			result, err := manager.ListJobs(rc)
			if err != nil {
				logger.Error("Failed to list cron jobs", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputJSONResult(result)
			}

			return outputTextResult(result)
		}),
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
	cmd.Flags().StringVarP(&user, "user", "u", "", "Specify user for crontab operations")

	return cmd
}

// newCronAddCmd creates the add subcommand
func newCronAddCmd() *cobra.Command {
	var (
		user       string
		comment    string
		dryRun     bool
		noBackup   bool
		template   string
	)

	cmd := &cobra.Command{
		Use:   "add <schedule> <command>",
		Short: "Add a new cron job",
		Long: `Add a new cron job with the specified schedule and command.

Schedule can be:
- Standard cron format: "0 2 * * *" (daily at 2 AM)
- Special expressions: @reboot, @yearly, @monthly, @weekly, @daily, @hourly
- Preset names: hourly, daily, weekly, monthly, yearly

Examples:
  eos manage cron add "0 2 * * *" "/backup.sh"
  eos manage cron add "@daily" "/cleanup.sh"
  eos manage cron add daily "/cleanup.sh"`,

		Args: cobra.ExactArgs(2),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			schedule := args[0]
			command := args[1]

			// Check if schedule is a preset
			if preset, exists := cron_management.CronSchedulePresets[schedule]; exists {
				schedule = preset
			}

			logger.Info("Adding cron job", 
				zap.String("schedule", schedule),
				zap.String("command", command),
				zap.String("user", user),
				zap.Bool("dry_run", dryRun))

			config := cron_management.DefaultCronConfig()
			config.User = user
			config.DryRun = dryRun
			config.CreateBackup = !noBackup

			job := &cron_management.CronJob{
				Schedule: schedule,
				Command:  command,
				Comment:  comment,
			}

			// Use template if specified
			if template != "" {
				for _, tmpl := range cron_management.CommonCronTemplates {
					if tmpl.Name == template {
						job.Schedule = tmpl.Schedule
						job.Command = tmpl.Command
						job.Comment = tmpl.Description
						break
					}
				}
			}

			manager := cron_management.NewCronManager(config)
			operation, err := manager.AddJob(rc, job)
			if err != nil {
				logger.Error("Failed to add cron job", zap.Error(err))
				return err
			}

			return outputOperationResult(operation)
		}),
	}

	cmd.Flags().StringVarP(&user, "user", "u", "", "Specify user for crontab operations")
	cmd.Flags().StringVarP(&comment, "comment", "c", "", "Add comment to the cron job")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&noBackup, "no-backup", false, "Skip creating backup before changes")
	cmd.Flags().StringVarP(&template, "template", "t", "", "Use predefined template (system_backup, log_rotation, etc.)")

	return cmd
}

// newCronRemoveCmd creates the remove subcommand
func newCronRemoveCmd() *cobra.Command {
	var (
		user     string
		dryRun   bool
		noBackup bool
	)

	cmd := &cobra.Command{
		Use:     "remove <job-id-or-line>",
		Aliases: []string{"rm", "delete", "del"},
		Short:   "Remove a cron job",
		Long: `Remove a cron job by ID or exact line match.

You can specify either:
- Job ID (8-character hash shown in list output)
- Exact cron line: "0 2 * * * /backup.sh"

Examples:
  eos manage cron remove abc12345
  eos manage cron remove "0 2 * * * /backup.sh"`,

		Args: cobra.ExactArgs(1),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			jobIdentifier := args[0]

			logger.Info("Removing cron job", 
				zap.String("identifier", jobIdentifier),
				zap.String("user", user),
				zap.Bool("dry_run", dryRun))

			config := cron_management.DefaultCronConfig()
			config.User = user
			config.DryRun = dryRun
			config.CreateBackup = !noBackup

			manager := cron_management.NewCronManager(config)
			operation, err := manager.RemoveJob(rc, jobIdentifier)
			if err != nil {
				logger.Error("Failed to remove cron job", zap.Error(err))
				return err
			}

			return outputOperationResult(operation)
		}),
	}

	cmd.Flags().StringVarP(&user, "user", "u", "", "Specify user for crontab operations")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&noBackup, "no-backup", false, "Skip creating backup before changes")

	return cmd
}

// newCronClearCmd creates the clear subcommand
func newCronClearCmd() *cobra.Command {
	var (
		user     string
		dryRun   bool
		noBackup bool
		force    bool
	)

	cmd := &cobra.Command{
		Use:     "clear",
		Aliases: []string{"purge", "removeall"},
		Short:   "Remove all cron jobs",
		Long: `Remove all cron jobs for the current or specified user.

This operation requires confirmation unless --force is used.`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if !force && !dryRun {
				fmt.Print("Are you sure you want to remove ALL cron jobs? [y/N]: ")
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" && response != "yes" {
					logger.Info("Operation cancelled by user")
					return nil
				}
			}

			logger.Info("Clearing all cron jobs", 
				zap.String("user", user),
				zap.Bool("dry_run", dryRun))

			config := cron_management.DefaultCronConfig()
			config.User = user
			config.DryRun = dryRun
			config.CreateBackup = !noBackup

			manager := cron_management.NewCronManager(config)
			operation, err := manager.ClearAllJobs(rc)
			if err != nil {
				logger.Error("Failed to clear cron jobs", zap.Error(err))
				return err
			}

			return outputOperationResult(operation)
		}),
	}

	cmd.Flags().StringVarP(&user, "user", "u", "", "Specify user for crontab operations")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&noBackup, "no-backup", false, "Skip creating backup before changes")
	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")

	return cmd
}

// newCronValidateCmd creates the validate subcommand
func newCronValidateCmd() *cobra.Command {
	var outputJSON bool

	cmd := &cobra.Command{
		Use:   "validate <cron-expression>",
		Short: "Validate a cron expression",
		Long: `Validate a cron expression and show its description.

Examples:
  eos manage cron validate "0 2 * * *"
  eos manage cron validate "@daily"
  eos manage cron validate "*/15 * * * *"`,

		Args: cobra.ExactArgs(1),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			expression := args[0]

			logger.Info("Validating cron expression", zap.String("expression", expression))

			manager := cron_management.NewCronManager(nil)
			result := manager.ValidateExpression(expression)

			if outputJSON {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			logger.Info("Cron expression validation", 
				zap.String("expression", result.Expression),
				zap.Bool("valid", result.Valid),
				zap.String("description", result.Description),
				zap.String("error", result.Error))

			if result.Valid {
				fmt.Printf("✓ Valid: %s\n", result.Description)
			} else {
				fmt.Printf("✗ Invalid: %s\n", result.Error)
			}

			return nil
		}),
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// Helper functions for output formatting

func outputJSONResult(result interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputTextResult(result *cron_management.CronListResult) error {
	if !result.HasCrontab {
		fmt.Printf("No crontab found for user: %s\n", result.User)
		return nil
	}

	fmt.Printf("Cron jobs for user: %s (%d jobs)\n", result.User, result.Count)
	fmt.Printf("Listed at: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	if len(result.Jobs) == 0 {
		fmt.Println("No jobs found.")
		return nil
	}

	fmt.Printf("%-10s %-20s %-50s %s\n", "ID", "Schedule", "Command", "Comment")
	fmt.Println(strings.Repeat("-", 100))

	for _, job := range result.Jobs {
		comment := job.Comment
		if comment == "" {
			comment = "-"
		}
		fmt.Printf("%-10s %-20s %-50s %s\n", 
			job.ID, 
			job.Schedule, 
			truncateString(job.Command, 48), 
			truncateString(comment, 20))
	}

	return nil
}

func outputOperationResult(operation *cron_management.CronOperation) error {
	if operation.DryRun {
		fmt.Printf("[DRY RUN] %s\n", operation.Message)
	} else if operation.Success {
		fmt.Printf("✓ %s\n", operation.Message)
	} else {
		fmt.Printf("✗ %s\n", operation.Message)
	}

	return nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}