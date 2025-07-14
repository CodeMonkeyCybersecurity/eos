package update

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CrontabCmd = &cobra.Command{
	Use:   "crontab",
	Short: "Update the crontab to send email alerts on job failures",
	Long: `Update the crontab to send email alerts on job failures.

Sets the MAILTO variable in the user's crontab so that cronjob failures will be emailed.
The command will automatically create a backup of the existing crontab before making changes.

Examples:
  eos update crontab --email admin@example.com    # Set email for cron alerts
  eos update crontab                              # Interactive prompt for email`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		// Get email from flag and trim
		email, _ := cmd.Flags().GetString("email")
		email = strings.TrimSpace(email)
		if email == "" {
			email = interaction.PromptInput(rc.Ctx, " Email address for cron failure alerts", "e.g., your@email.com")
		}
		if email == "" {
			log.Error("No email address provided. Aborting update.")
			return fmt.Errorf("email address is required")
		}

		log.Info(" Fetching current crontab...")
		current, err := eos_unix.GetCrontab()
		if err != nil {
			log.Error(" Failed to retrieve crontab", zap.Error(err))
			return err
		}

		log.Info("🛟 Creating backup of existing crontab...")
		backupPath, err := eos_unix.BackupCrontab(current)
		if err != nil {
			log.Warn("Could not create crontab backup", zap.Error(err))
		} else {
			log.Info(" Crontab backup saved", zap.String("path", backupPath))
		}

		log.Info(" Patching crontab with MAILTO directive", zap.String("mailto", email))
		updated := eos_unix.PatchMailto(current, email)

		log.Info(" Applying updated crontab...")
		if err := eos_unix.SetCrontab(updated); err != nil {
			log.Error(" Failed to apply updated crontab", zap.Error(err))
			return err
		}

		log.Info(" Crontab updated successfully", zap.String("mailto", email))
		log.Info("terminal prompt: New crontab:")
		log.Info("terminal prompt: ==============================")
		fmt.Println(updated)
		log.Info("terminal prompt: ==============================")

		return nil
	}),
}

func init() {
	CrontabCmd.Flags().String("email", "", "Email address for cron failure alerts")
	UpdateCmd.AddCommand(CrontabCmd)
}
