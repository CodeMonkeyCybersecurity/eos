package python

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallPackages installs Python packages based on the operating system
// Migrated from cmd/list/preflight-install.go (installLinuxPackages, installMacOSPackages, etc.)
func InstallPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Detect operating system
	logger.Info("Assessing system for Python package installation")

	osType := runtime.GOOS
	logger.Info("Detected operating system", zap.String("os", osType))

	// Check Python version
	pythonCmd := exec.Command("python3", "--version")
	pythonOutput, err := pythonCmd.Output()
	if err != nil {
		logger.Error("Python 3 not found", zap.Error(err))
		return err
	}
	logger.Info("Python version", zap.String("version", strings.TrimSpace(string(pythonOutput))))

	// INTERVENE - Install based on OS
	switch osType {
	case "linux":
		return installLinuxPackages(rc)
	case "darwin":
		return installMacOSPackages(rc)
	default:
		logger.Warn("Unsupported OS, attempting pip3 installation", zap.String("os", osType))
		return installWithPip3(rc, false)
	}
}

// installLinuxPackages installs Python packages on Linux systems
// Migrated from cmd/list/preflight-install.go installLinuxPackages
func installLinuxPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if this is a Debian/Ubuntu system
	if isDebian, err := platform.IsDebianBased(rc); err == nil && isDebian {
		logger.Info("Detected Debian/Ubuntu system, using apt package manager")
		return installDebianPackages(rc)
	}

	logger.Info("Non-Debian Linux system, attempting pip3 with fallback options")
	return installWithPip3(rc, true)
}

// installDebianPackages installs Python packages using apt on Debian/Ubuntu
// Migrated from cmd/list/preflight-install.go installDebianPackages
func installDebianPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get Debian package names
	logger.Info("Assessing Debian package requirements")

	debianPackages := GetDebianPackageNames()

	logger.Info("Installing Debian packages",
		zap.Strings("packages", debianPackages),
		zap.Int("count", len(debianPackages)))

	// INTERVENE - Update apt cache first
	logger.Info("Updating apt package cache")
	updateCmd := exec.Command("sudo", "apt", "update")
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr
	if err := updateCmd.Run(); err != nil {
		logger.Warn("apt update failed, continuing anyway", zap.Error(err))
	}

	// Install packages
	installArgs := append([]string{"apt", "install", "-y"}, debianPackages...)
	logger.Info("Installing packages with apt",
		zap.String("command", "sudo"),
		zap.Strings("args", installArgs))

	installCmd := exec.Command("sudo", installArgs...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	installCmd.Stdin = os.Stdin

	if err := installCmd.Run(); err != nil {
		logger.Error("apt package installation failed", zap.Error(err))
		return err
	}

	logger.Info("Debian packages installed successfully")

	// Install packages not available as Debian packages separately with pip3
	pipPackages := GetPipOnlyPackages()
	logger.Info("Installing additional Python packages with pip3",
		zap.Strings("packages", pipPackages))

	pipCmd := exec.Command("sudo", append([]string{"pip3", "install", "--break-system-packages"}, pipPackages...)...)
	pipCmd.Stdout = os.Stdout
	pipCmd.Stderr = os.Stderr
	if err := pipCmd.Run(); err != nil {
		logger.Warn("Failed to install some pip3 packages",
			zap.Error(err),
			zap.Strings("packages", pipPackages))
	} else {
		logger.Info("Additional pip3 packages installed successfully")
	}

	// EVALUATE - Verify installation
	return VerifyAllPackages(rc)
}

// installMacOSPackages installs Python packages on macOS
// Migrated from cmd/list/preflight-install.go installMacOSPackages
func installMacOSPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - macOS uses pip3 directly
	logger.Info("Detected macOS, using pip3 directly")

	// INTERVENE & EVALUATE - Use pip3
	return installWithPip3(rc, false)
}

// installWithPip3 installs packages using pip3 with optional system package breaking
// Migrated from cmd/list/preflight-install.go installWithPip3
func installWithPip3(rc *eos_io.RuntimeContext, useBreakSystemPackages bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get packages to install
	logger.Info("Assessing pip3 installation requirements")

	packages := GetDelphiPackages()
	packageNames := make([]string, len(packages))
	for i, pkg := range packages {
		packageNames[i] = pkg.PipName
	}

	logger.Info("Installing Python packages with pip3",
		zap.Strings("packages", packageNames),
		zap.Int("count", len(packageNames)),
		zap.Bool("break_system_packages", useBreakSystemPackages))

	// Check if pip3 is available
	pip3Path, err := exec.LookPath("pip3")
	if err != nil {
		logger.Error("pip3 not found", zap.Error(err))
		return err
	}
	logger.Info("Found pip3", zap.String("path", pip3Path))

	// INTERVENE - Build and execute install command
	var installArgs []string
	if useBreakSystemPackages {
		installArgs = append([]string{"pip3", "install", "--break-system-packages", "--upgrade"}, packageNames...)
	} else {
		installArgs = append([]string{"pip3", "install", "--upgrade"}, packageNames...)
	}

	logger.Info("Executing pip install command",
		zap.String("command", "sudo"),
		zap.Strings("args", installArgs))

	installCmd := exec.Command("sudo", installArgs...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	installCmd.Stdin = os.Stdin

	if err := installCmd.Run(); err != nil {
		logger.Error("pip3 installation failed",
			zap.Error(err),
			zap.Strings("packages", packageNames))
		return err
	}

	logger.Info("pip3 packages installed successfully")

	// EVALUATE - Verify installation
	return VerifyAllPackages(rc)
}
