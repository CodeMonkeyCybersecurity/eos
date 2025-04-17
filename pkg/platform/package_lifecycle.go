package platform

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"go.uber.org/zap"
)

func PackageUpdate(cron bool) error {
	log := logger.GetLogger()
	osPlatform := GetOSPlatform()
	log.Info("Detected OS", zap.String("os", osPlatform))

	if cron {
		log.Info("Scheduling cron job for package update")
		return scheduleCron("eos update packages", osPlatform, log)
	}

	switch osPlatform {
	case "linux":
		distro := DetectLinuxDistro()
		switch distro {
		case "rhel":
			return runDnfWithRetry("")
		case "debian":
			return runAndLog("apt update && apt upgrade -y && apt autoremove -y && apt autoclean -y", "bash", "-c")
		default:
			log.Warn("Unknown Linux distro; defaulting to Debian-style update")
			return runAndLog("apt update && apt upgrade -y && apt autoremove -y && apt autoclean -y", "bash", "-c")
		}
	case "macos":
		return runAndLog("brew update && brew upgrade && brew cleanup", "bash", "-c")
	case "windows":
		return runAndLog("winget update --all", "cmd", "/C")
	default:
		return fmt.Errorf("unsupported OS: %s", osPlatform)
	}
}

func runDnfWithRetry(pkgName string) error {
	log := logger.GetLogger()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := []string{"install", "-y"}
	if pkgName != "" {
		args = append(args, pkgName)
	}
	cmd := exec.CommandContext(ctx, "dnf", args...)

	log.Info("Running DNF install", zap.Strings("args", args))
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		log.Warn("DNF timed out. Running mirror recovery...")

		if err := exec.Command("dnf", "clean", "all").Run(); err != nil {
			log.Warn("Failed to clean DNF cache", zap.Error(err))
		}
		makecache := exec.Command("dnf", "--setopt=timeout=10", "--setopt=retries=0", "--setopt=fastestmirror=True", "makecache")
		if out, err := makecache.CombinedOutput(); err != nil {
			log.Error("DNF makecache failed", zap.ByteString("output", out), zap.Error(err))
			return err
		}

		log.Info("Retrying DNF install")
		retryCmd := exec.Command("dnf", args...)
		retryOut, retryErr := retryCmd.CombinedOutput()
		if retryErr != nil {
			log.Error("Retry failed", zap.ByteString("output", retryOut), zap.Error(retryErr))
			return retryErr
		}
		log.Info("DNF retry succeeded", zap.ByteString("output", retryOut))
		return nil
	}

	if err != nil {
		log.Error("DNF failed", zap.ByteString("output", out), zap.Error(err))
	}
	return err
}

func runAndLog(cmd, shell string, shellArg string) error {
	log := logger.GetLogger()
	log.Info("Running update command", zap.String("cmd", cmd))
	err := execute.ExecuteAndLog(shell, shellArg, cmd)
	if err != nil {
		log.Error("Update command failed", zap.Error(err))
	}
	return err
}
