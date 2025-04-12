/* cmd/update/packages.go */
package update

import (
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var Cron bool

var UpdatePackagesCmd = &cobra.Command{
	Use:     "packages",
	Aliases: []string{"pkgs"},
	Short:   "Update system packages based on detected OS",
	Long:    "Detects the host OS and executes appropriate update and cleanup commands. Supports scheduling via --cron.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		osPlatform := platform.GetOSPlatform()
		log.Info("Detected OS", zap.String("os", osPlatform))

		var updateCmd string
		switch osPlatform {
		case "linux":
			// Use the helper to detect the Linux distro type.
			distro := platform.DetectLinuxDistro()
			if distro == "rhel" {
				updateCmd = "dnf upgrade --refresh -y && dnf autoremove -y && dnf clean all"
				log.Info("Detected RHEL-based system")
			} else if distro == "debian" {
				updateCmd = "apt update -y && apt upgrade -y && apt autoremove -y && apt autoclean -y"
				log.Info("Detected Debian-based system")
			} else {
				log.Warn("Unrecognized Linux distribution, defaulting to Debian-based update command")
				updateCmd = "apt update -y && apt upgrade -y && apt autoremove -y && apt autoclean -y"
			}
		case "macos":
			updateCmd = "brew update && brew upgrade && brew cleanup"
			log.Info("Detected macOS")
		case "windows":
			updateCmd = "winget update --all"
			log.Info("Detected Windows")
		default:
			log.Error("Unsupported OS", zap.String("os", osPlatform))
			return fmt.Errorf("unsupported OS: %s", osPlatform)
		}

		if Cron {
			log.Info("Scheduling cron job for package update")
			return scheduleCron(updateCmd, osPlatform)
		}

		log.Info("Running update command", zap.String("cmd", updateCmd))
		var err error
		// Use appropriate shell depending on the OS.
		if osPlatform == "windows" {
			err = exec.Command("cmd", "/C", updateCmd).Run()
		} else {
			err = exec.Command("bash", "-c", updateCmd).Run()
		}
		if err != nil {
			log.Error("Failed to execute update command", zap.Error(err))
			return err
		}

		log.Info("Package update completed successfully")
		return nil
	}),
}

func scheduleCron(cmd string, osPlatform string) error {
	// Generate a random update time.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hour := r.Intn(24)
	minute := r.Intn(60)

	schedule := fmt.Sprintf("%d %d * * * %s", minute, hour, cmd)
	log.Info("Generated cron schedule", zap.String("schedule", schedule))
	log.Info("Scheduled update time", zap.Int("hour", hour), zap.Int("minute", minute))

	// Check for existing cron jobs that already run this command.
	existing, err := exec.Command("crontab", "-l").Output()
	if err == nil && len(existing) > 0 {
		if strings.Contains(string(existing), cmd) {
			log.Debug("Current crontab contents", zap.String("output", string(existing)))
			log.Warn("Cron job for this update command already exists — skipping scheduling")
			return nil
		}
	}

	switch osPlatform {
	case "linux", "macos":
		crontabCmd := fmt.Sprintf("(crontab -l 2>/dev/null; echo \"%s\") | crontab -", schedule)
		err := exec.Command("bash", "-c", crontabCmd).Run()
		if err != nil {
			log.Error("Failed to schedule cron job", zap.Error(err))
			return err
		}
		log.Info("Cron job successfully scheduled")
		log.Info("Cron job created", zap.String("schedule", schedule))
		log.Info("Cron job command", zap.String("command", cmd))
		log.Info("Cron job time", zap.Int("hour", hour), zap.Int("minute", minute))
		// Read back the crontab to confirm.
		out, err := exec.Command("crontab", "-l").Output()
		if err != nil {
			log.Error("Failed to read back crontab after writing", zap.Error(err))
		} else {
			log.Info("Updated crontab contents", zap.String("crontab", string(out)))
		}
	case "windows":
		taskName := "EosSystemUpdate"
		timeStr := fmt.Sprintf("%02d:%02d", hour, minute)
		createTask := exec.Command("schtasks", "/Create", "/SC", "DAILY", "/TN", taskName, "/TR", cmd, "/ST", timeStr)
		err = createTask.Run()
		if err != nil {
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

func init() {
	UpdateCmd.AddCommand(UpdatePackagesCmd)
	UpdatePackagesCmd.Flags().BoolVar(&Cron, "cron", false, "Schedule this update to run daily at a random time")
}
