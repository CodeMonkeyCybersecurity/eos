package platform

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"go.uber.org/zap"
)

func PackageUpdate(cron bool) error {
	osPlatform := GetOSPlatform()
	zap.L().Info("Detected OS", zap.String("os", osPlatform))

	if cron {
		zap.L().Info("Scheduling cron job for package update")
		return scheduleCron("eos update packages", osPlatform)
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
			zap.L().Warn("Unknown Linux distro; defaulting to Debian-style update")
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := []string{"install", "-y"}
	if pkgName != "" {
		args = append(args, pkgName)
	}
	cmd := exec.CommandContext(ctx, "dnf", args...)

	zap.L().Info("Running DNF install", zap.Strings("args", args))
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		zap.L().Warn("DNF timed out. Running mirror recovery...")

		if err := exec.Command("sudo", "dnf", "clean", "all").Run(); err != nil {
			zap.L().Error("Failed to clean DNF cache", zap.Error(err))
			return err
		}

		makecache := exec.Command("sudo", "dnf", "--setopt=timeout=10", "--setopt=retries=0", "--setopt=fastestmirror=True", "makecache")
		if out, err := makecache.CombinedOutput(); err != nil {
			zap.L().Error("DNF makecache failed", zap.ByteString("output", out), zap.Error(err))
			return err
		}

		zap.L().Info("Retrying DNF install")
		retryCmd := exec.Command("sudo", append([]string{"dnf"}, args...)...)
		retryOut, retryErr := retryCmd.CombinedOutput()
		if retryErr != nil {
			zap.L().Error("Retry failed", zap.ByteString("output", retryOut), zap.Error(retryErr))
			return retryErr
		}
		zap.L().Info("DNF retry succeeded", zap.ByteString("output", retryOut))
		return nil
	}

	if err != nil {
		zap.L().Error("DNF failed", zap.ByteString("output", out), zap.Error(err))
	}
	return err
}

func runAndLog(cmd string, shell string, shellArg string) error {

	zap.L().Info("Running update command", zap.String("cmd", cmd))
	execCmd := exec.Command(shell, shellArg, cmd)
	out, err := execCmd.CombinedOutput()
	if err != nil {
		zap.L().Error("Update command failed", zap.Error(err), zap.ByteString("output", out))
	}
	return err
}
