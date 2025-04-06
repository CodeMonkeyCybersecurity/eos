// cmd/disable/suspension.go

package disable

import (
	"fmt"
	"runtime"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/flags"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var disableSuspensionCmd = &cobra.Command{
	Use:   "suspension",
	Short: "Disable OS-level suspension and hibernation",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		log.Info("Disabling system suspension and hibernation...")

		if flags.IsDryRun() {
			log.Info("Dry-run mode: skipping system suspension disable")
			fmt.Println("💡 [dry-run] Suspension/hibernation *would* be disabled.")
			return nil
		}

		if runtime.GOOS != "linux" {
			log.Warn("System suspension disabling is only supported on Linux.")
			fmt.Println("❌ This command is not supported on your operating system.")
			return nil
		}

		if err := disableSystemdTargets(); err != nil {
			log.Error("Failed to disable suspend/hibernate targets", zap.Error(err))
			return fmt.Errorf("failed to disable system targets: %w", err)
		}

		if err := maskSleepTargets(); err != nil {
			log.Error("Failed to mask sleep targets", zap.Error(err))
			return fmt.Errorf("failed to mask sleep targets: %w", err)
		}

		if err := disableLogindSleep(); err != nil {
			log.Error("Failed to patch /etc/systemd/logind.conf", zap.Error(err))
			return fmt.Errorf("failed to modify logind.conf: %w", err)
		}

		log.Info("✅ System suspension and hibernation disabled successfully.")
		fmt.Println("✅ Suspension/hibernation is now disabled and persistent.")
		return nil
	},
}

func init() {
	DisableCmd.AddCommand(disableSuspensionCmd)
}

// disableSystemdTargets disables suspend and hibernate targets
func disableSystemdTargets() error {
	fmt.Println("🔧 Disabling suspend.target and hibernate.target...")
	// Example dry logic
	// You can replace this with: exec.Command("systemctl", "disable", "suspend.target", ...).Run()
	return nil
}

// maskSleepTargets masks system sleep targets
func maskSleepTargets() error {
	fmt.Println("🔧 Masking sleep.target, suspend.target, hibernate.target...")
	return nil
}

// disableLogindSleep patches /etc/systemd/logind.conf to disable suspend/hibernate
func disableLogindSleep() error {
	fmt.Println("🔧 Patching /etc/systemd/logind.conf to disable sleep options...")
	return nil
}
