package platform

import (
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func PackageUpdate(rc *eos_io.RuntimeContext, cron bool) error {
	osPlatform := GetOSPlatform()
	otelzap.Ctx(rc.Ctx).Info("Detected OS", zap.String("os", osPlatform))

	if cron {
		otelzap.Ctx(rc.Ctx).Info("Scheduling cron job for package update")
		return scheduleCron(rc, "eos update packages", osPlatform)
	}

	switch osPlatform {
	case "linux":
		distro := DetectLinuxDistro(rc)
		switch distro {
		case "rhel":
			return runDnfWithRetry(rc, "")
		case "debian":
			return runAndLog(rc, "apt update && apt upgrade -y && apt autoremove -y && apt autoclean -y", "bash", "-c")
		default:
			otelzap.Ctx(rc.Ctx).Warn("Unknown Linux distro; defaulting to Debian-style update")
			return runAndLog(rc, "apt update && apt upgrade -y && apt autoremove -y && apt autoclean -y", "bash", "-c")
		}
	case "macos":
		return runAndLog(rc, "brew update && brew upgrade && brew cleanup", "bash", "-c")
	case "windows":
		return runAndLog(rc, "winget update --all", "cmd", "/C")
	default:
		return fmt.Errorf("unsupported OS: %s", osPlatform)
	}
}

func runDnfWithRetry(rc *eos_io.RuntimeContext, pkgName string) error {

	args := []string{"install", "-y"}
	if pkgName != "" {
		args = append(args, pkgName)
	}

	otelzap.Ctx(rc.Ctx).Info("Running DNF install", zap.Strings("args", args))

	otelzap.Ctx(rc.Ctx).Warn("DNF timed out. Running mirror recovery...")

	cleanCmd := exec.Command("dnf", "clean", "all")
	if err := cleanCmd.Run(); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to clean DNF cache", zap.Error(err))
		return err
	}

	makecache := exec.Command("dnf", "--setopt=timeout=10", "--setopt=retries=0", "--setopt=fastestmirror=True", "makecache")
	if out, err := makecache.CombinedOutput(); err != nil {
		otelzap.Ctx(rc.Ctx).Error("DNF makecache failed", zap.ByteString("output", out), zap.Error(err))
		return err
	}

	otelzap.Ctx(rc.Ctx).Info("Retrying DNF install")
	retryCmd := exec.Command("dnf", args...)
	retryOut, retryErr := retryCmd.CombinedOutput()
	if retryErr != nil {
		otelzap.Ctx(rc.Ctx).Error("Retry failed", zap.ByteString("output", retryOut), zap.Error(retryErr))
		return retryErr
	}
	otelzap.Ctx(rc.Ctx).Info("DNF retry succeeded", zap.ByteString("output", retryOut))
	return nil

}

func runAndLog(rc *eos_io.RuntimeContext, cmd string, shell string, shellArg string) error {

	otelzap.Ctx(rc.Ctx).Info("Running update command", zap.String("cmd", cmd))
	execCmd := exec.Command(shell, shellArg, cmd)
	out, err := execCmd.CombinedOutput()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Update command failed", zap.Error(err), zap.ByteString("output", out))
	}
	return err
}
