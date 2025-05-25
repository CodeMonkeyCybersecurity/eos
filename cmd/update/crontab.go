package update

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var email string

var CrontabCmd = &cobra.Command{
	Use:   "crontab",
	Short: "Update the crontab to send email alerts on job failures",
	Long:  "Sets the MAILTO variable in the user's crontab so that cronjob failures will be emailed.",
	RunE:  eos.Wrap(runCrontabUpdate),
}

func init() {
	CrontabCmd.Flags().StringVar(&email, "email", "", "Email address for cron failure alerts")
	UpdateCmd.AddCommand(CrontabCmd)
}

func runCrontabUpdate(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := ctx.Log.Named("crontab")

	// Trim and prompt if needed
	email = strings.TrimSpace(email)
	if email == "" {
		email = interaction.PromptInput("📧 Email address for cron failure alerts", "e.g., your@email.com")
	}
	if email == "" {
		log.Error("No email address provided. Aborting update.")
		return fmt.Errorf("email address is required")
	}

	log.Info("🔍 Fetching current crontab...")
	current, err := eos_unix.GetCrontab()
	if err != nil {
		log.Error("❌ Failed to retrieve crontab", zap.Error(err))
		return err
	}

	log.Info("🛟 Creating backup of existing crontab...")
	backupPath, err := eos_unix.BackupCrontab(current)
	if err != nil {
		log.Warn("⚠️ Could not create crontab backup", zap.Error(err))
	} else {
		log.Info("✅ Crontab backup saved", zap.String("path", backupPath))
	}

	log.Info("✏️ Patching crontab with MAILTO directive", zap.String("mailto", email))
	updated := eos_unix.PatchMailto(current, email)

	log.Info("📤 Applying updated crontab...")
	if err := eos_unix.SetCrontab(updated); err != nil {
		log.Error("❌ Failed to apply updated crontab", zap.Error(err))
		return err
	}

	log.Info("✅ Crontab updated successfully", zap.String("mailto", email))
	fmt.Println("\n📜 New crontab:\n==============================")
	fmt.Println(updated)
	fmt.Println("==============================")

	return nil
}
