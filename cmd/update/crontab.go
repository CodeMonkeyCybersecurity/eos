// cmd/update/crontab.go
package update

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var email string

var CrontabCmd = &cobra.Command{
	Use:   "crontab",
	Short: "Update the crontab to send email alerts on job failures",
	Long:  "Sets the MAILTO variable in the user's crontab so that cronjob failures will be emailed.",
	RunE:  runCrontabUpdate,
}

func init() {
	UpdateCmd.AddCommand(CrontabCmd)
	CrontabCmd.Flags().StringVar(&email, "email", "", "Email address for cron failure alerts")
	UpdateCmd.AddCommand(CrontabCmd)
}

func runCrontabUpdate(cmd *cobra.Command, args []string) error {
	log := logger.L()

	if strings.TrimSpace(email) == "" {
		email = interaction.PromptInput("Email address for cron failure alerts", "e.g., your@email.com")
	}

	if strings.TrimSpace(email) == "" {
		log.Error("No email provided. Aborting.")
		return fmt.Errorf("email address is required")
	}

	current, err := system.GetCrontab()
	if err != nil {
		log.Error("Could not retrieve crontab", zap.Error(err))
		return err
	}

	backupPath, err := system.BackupCrontab(current)
	if err != nil {
		log.Warn("Could not backup crontab", zap.Error(err))
	} else {
		log.Info("Crontab backup created", zap.String("path", backupPath))
	}

	updated := system.PatchMailto(current, email)

	if flags.IsDryRun() {
		fmt.Println("🧪 Dry run mode: this is what your crontab would look like:")
		fmt.Println("\n==============================")
		fmt.Println(updated)
		fmt.Println("==============================")
		return nil
	}

	if err := system.SetCrontab(updated); err != nil {
		log.Error("Failed to apply crontab changes", zap.Error(err))
		return err
	}

	fmt.Println("✅ Crontab updated with MAILTO=", email)
	fmt.Println("\n📜 New crontab:\n==============================")
	fmt.Println(updated)
	fmt.Println("==============================")

	return nil
}
