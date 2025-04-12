/* pkg/platform/lifecycle.go */

package platform

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"go.uber.org/zap"
)

// RunPackageUpdate detects the OS and runs the appropriate package update command.
// If cron is true, a cron (or Windows scheduled task) is created at a random time.
func RunPackageUpdate(cron bool) error {
	log := logger.GetLogger()
	osPlatform := GetOSPlatform()
	log.Info("Detected OS", zap.String("os", osPlatform))

	var updateCmd string
	switch osPlatform {
	case "linux":
		// Detect the Linux distro to decide on the update command.
		distro := DetectLinuxDistro()
		switch distro {
		case "rhel":
			updateCmd = "dnf upgrade --refresh -y && dnf autoremove -y && dnf clean all"
			log.Info("Detected RHEL-based system")
		case "debian":
			updateCmd = "apt update && apt upgrade -y && apt autoremove -y && apt autoclean -y"
			log.Info("Detected Debian-based system")
		default:
			log.Warn("Unrecognized Linux distribution, defaulting to Debian-based update command")
			updateCmd = "apt update && apt upgrade -y && apt autoremove -y && apt autoclean -y"
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

	if cron {
		log.Info("Scheduling cron job for package update")
		return scheduleCron(updateCmd, osPlatform, log)
	}

	log.Info("Running update command", zap.String("cmd", updateCmd))
	var err error
	// Use ExecuteAndLog to run the update command under the correct shell.
	if osPlatform == "windows" {
		err = execute.ExecuteAndLog("cmd", "/C", updateCmd)
	} else {
		err = execute.ExecuteAndLog("bash", "-c", updateCmd)
	}
	if err != nil {
		log.Error("Failed to execute update command", zap.Error(err))
		return err
	}

	log.Info("Package update completed successfully")
	return nil
}
