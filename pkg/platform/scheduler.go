/* pkg/platform/scheduler.go */

package platform

import (
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// scheduleCron sets up a scheduled task (cron for Linux/macOS; schtasks for Windows) to run the update command.
func scheduleCron(cmd string, osPlatform string, log *zap.Logger) error {
	// Generate a random time.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hour := r.Intn(24)
	minute := r.Intn(60)

	// Create a cron schedule string: "minute hour * * * command"
	schedule := fmt.Sprintf("%d %d * * * %s", minute, hour, cmd)
	log.Info("Generated cron schedule", zap.String("schedule", schedule))
	log.Info("Scheduled update time", zap.Int("hour", hour), zap.Int("minute", minute))

	// Check for an existing crontab entry that contains the command.
	existing, err := exec.Command("crontab", "-l").Output()
	if err == nil && len(existing) > 0 {
		if strings.Contains(string(existing), cmd) {
			log.Debug("Cron job for this update command already exists — skipping scheduling", zap.String("existing", string(existing)))
			return nil
		}
	}

	switch osPlatform {
	case "linux", "macos":
		// Append the new schedule to the existing crontab.
		crontabCmd := fmt.Sprintf("(crontab -l 2>/dev/null; echo \"%s\") | crontab -", schedule)
		if err := execute.ExecuteAndLog("bash", "-c", crontabCmd); err != nil {
			log.Error("Failed to schedule cron job", zap.Error(err))
			return err
		}
		log.Info("Cron job successfully scheduled", zap.String("schedule", schedule))
		// Optionally, read back the crontab to confirm.
		out, err := exec.Command("crontab", "-l").Output()
		if err != nil {
			log.Error("Failed to read back crontab after writing", zap.Error(err))
		} else {
			log.Info("Updated crontab contents", zap.String("crontab", string(out)))
		}
	case "windows":
		taskName := "EosSystemUpdate"
		timeStr := fmt.Sprintf("%02d:%02d", hour, minute)
		if err := execute.ExecuteAndLog("schtasks", "/Create", "/SC", "DAILY", "/TN", taskName, "/TR", cmd, "/ST", timeStr); err != nil {
			log.Error("Failed to schedule Windows task", zap.Error(err))
			return err
		}
		log.Info("Windows scheduled task created", zap.String("task", taskName), zap.String("time", timeStr))
	default:
		log.Error("Cron scheduling not supported on this OS", zap.String("os", osPlatform))
		return fmt.Errorf("cron scheduling not supported on: %s", osPlatform)
	}

	return nil
}
