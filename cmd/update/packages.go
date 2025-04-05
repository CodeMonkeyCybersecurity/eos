// cmd/update/packages.go
package update

import (
	"fmt"
	"math/rand"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var Cron bool

var UpdatePackagesCmd = &cobra.Command{
	Use:   "packages",
	Short: "Update system packages based on detected OS",
	Long:  "Detects the host OS and executes appropriate update and cleanup commands. Supports scheduling via --cron.",
	RunE: func(cmd *cobra.Command, args []string) error {

		osType := runtime.GOOS
		log.Info("Detected OS", zap.String("os", osType))

		var updateCmd string
		switch osType {
		case "linux":
			if isRHEL() {
				updateCmd = "yum update -y && yum upgrade -y && yum autoremove -y"
				log.Info("Detected RHEL-based system")
			} else {
				updateCmd = "apt update -y && apt upgrade -y && apt autoremove -y && apt autoclean -y"
				log.Info("Detected Debian-based system")
			}
		case "darwin":
			updateCmd = "brew update && brew upgrade && brew cleanup"
			log.Info("Detected macOS")
		case "windows":
			updateCmd = "winget upgrade --all"
			log.Info("Detected Windows")
		default:
			log.Error("Unsupported OS", zap.String("os", osType))
			return fmt.Errorf("unsupported OS: %s", osType)
		}

		if Cron {
			log.Info("Scheduling cron job for package update")
			return scheduleCron(updateCmd, osType)
		}

		log.Info("Running update command", zap.String("cmd", updateCmd))
		err := exec.Command("bash", "-c", updateCmd).Run()
		if err != nil {
			log.Error("Failed to execute update command", zap.Error(err))
			return err
		}

		log.Info("Package update completed successfully")
		return nil
	},
}

func isRHEL() bool {
	out, err := exec.Command("grep", "-i", "rhel", "/etc/os-release").Output()
	return err == nil && len(out) > 0
}

func scheduleCron(cmd string, osType string) error {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hour := r.Intn(24)
	minute := r.Intn(60)

	schedule := fmt.Sprintf("%d %d * * * %s", minute, hour, cmd)
	log.Info("Generated cron schedule", zap.String("schedule", schedule))

	// Check for existing cron jobs that already run this command
	existing, err := exec.Command("crontab", "-l").Output()
	if err == nil && len(existing) > 0 {
		if strings.Contains(string(existing), cmd) {
			log.Warn("Cron job for this update command already exists — skipping scheduling")
			return nil
		}
	}

	switch osType {
	case "linux", "darwin":
		crontabCmd := fmt.Sprintf("(crontab -l 2>/dev/null; echo \"%s\") | crontab -", schedule)
		err := exec.Command("bash", "-c", crontabCmd).Run()
		if err != nil {
			log.Error("Failed to schedule cron job", zap.Error(err))
			return err
		}
		log.Info("Cron job successfully scheduled")
	case "windows":
		taskName := "EosSystemUpdate"
		timeStr := fmt.Sprintf("%02d:%02d", hour, minute)
		createTask := exec.Command("schtasks", "/Create", "/SC", "DAILY", "/TN", taskName, "/TR", cmd, "/ST", timeStr)
		err := createTask.Run()
		if err != nil {
			log.Error("Failed to schedule Windows task", zap.Error(err))
			return err
		}
		log.Info("Windows scheduled task created", zap.String("task", taskName), zap.String("time", timeStr))
	default:
		log.Error("Cron scheduling not supported on this OS", zap.String("os", osType))
		return fmt.Errorf("cron scheduling not supported on: %s", osType)
	}

	return nil
}

func init() {
	UpdateCmd.AddCommand(UpdatePackagesCmd)

	UpdatePackagesCmd.Flags().BoolVar(&Cron, "cron", false, "Schedule this update to run daily at a random time")
}
