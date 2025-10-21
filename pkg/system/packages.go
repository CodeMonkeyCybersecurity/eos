// pkg/system/packages.go
//
// System package manager operations - pure business logic
// Supports apt, yum, dnf, pacman

package system

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PackageManager represents supported package managers
type PackageManager string

const (
	PackageManagerApt    PackageManager = "apt"
	PackageManagerYum    PackageManager = "yum"
	PackageManagerDnf    PackageManager = "dnf"
	PackageManagerPacman PackageManager = "pacman"
	PackageManagerNone   PackageManager = ""
)

// DetectPackageManager detects which package manager is available on the system
func DetectPackageManager() PackageManager {
	managers := []PackageManager{
		PackageManagerApt,
		PackageManagerDnf,
		PackageManagerYum,
		PackageManagerPacman,
	}

	for _, mgr := range managers {
		if _, err := exec.LookPath(string(mgr)); err == nil {
			return mgr
		}
	}

	return PackageManagerNone
}

// UpdateSystemPackages updates all system packages using the specified package manager
// Requires root privileges
func UpdateSystemPackages(rc *eos_io.RuntimeContext, manager PackageManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("system package updates require root privileges - run with sudo")
	}

	logger.Info("Updating system packages", zap.String("manager", string(manager)))

	switch manager {
	case PackageManagerApt:
		return updateApt(rc)
	case PackageManagerYum, PackageManagerDnf:
		return updateYumDnf(rc, manager)
	case PackageManagerPacman:
		return updatePacman(rc)
	default:
		return fmt.Errorf("unsupported package manager: %s", manager)
	}
}

// updateApt runs apt update && apt upgrade
func updateApt(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Step 1: apt update (refresh package lists)
	logger.Info("Refreshing package lists (apt update)")
	updateCmd := exec.Command("apt", "update")
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr

	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("apt update failed: %w", err)
	}

	logger.Info("Package lists updated")

	// Step 2: apt upgrade (install updates)
	logger.Info("Installing package updates (apt upgrade)")
	upgradeCmd := exec.Command("apt", "upgrade", "-y")
	upgradeCmd.Stdout = os.Stdout
	upgradeCmd.Stderr = os.Stderr

	if err := upgradeCmd.Run(); err != nil {
		return fmt.Errorf("apt upgrade failed: %w", err)
	}

	// Step 3: apt autoremove (remove old packages)
	logger.Info("Removing old packages (apt autoremove)")
	removeCmd := exec.Command("apt", "autoremove", "-y")
	removeCmd.Stdout = os.Stdout
	removeCmd.Stderr = os.Stderr

	if err := removeCmd.Run(); err != nil {
		return fmt.Errorf("apt autoremove failed: %w", err)
	}


	// Step 4: apt autoclean (remove old packages)
	logger.Info("Cleaning up old packages (apt autoclean)")
	cleanCmd := exec.Command("apt", "autoclean", "-y")
	cleanCmd.Stdout = os.Stdout
	cleanCmd.Stderr = os.Stderr

	if err := cleanCmd.Run(); err != nil {
		return fmt.Errorf("apt autoclean failed: %w", err)
	}

	logger.Info("System packages updated successfully")
	return nil
}

// updateYumDnf runs yum/dnf update
func updateYumDnf(rc *eos_io.RuntimeContext, manager PackageManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating packages", zap.String("manager", string(manager)))
	updateCmd := exec.Command(string(manager), "update", "-y")
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr

	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("%s update failed: %w", manager, err)
	}

	logger.Info("System packages updated successfully")
	return nil
}

// updatePacman runs pacman -Syu
func updatePacman(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating packages (pacman -Syu)")
	updateCmd := exec.Command("pacman", "-Syu", "--noconfirm")
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr

	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("pacman update failed: %w", err)
	}

	logger.Info("System packages updated successfully")
	return nil
}

// InstallPackages installs the specified packages using the package manager
// Requires root privileges
func InstallPackages(rc *eos_io.RuntimeContext, manager PackageManager, packages []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(packages) == 0 {
		return nil
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing system packages requires root privileges - run with sudo")
	}

	logger.Info("Installing packages",
		zap.String("manager", string(manager)),
		zap.Strings("packages", packages))

	var installCmd *exec.Cmd

	switch manager {
	case PackageManagerApt:
		// Update package lists first
		logger.Info("Updating package lists")
		updateCmd := exec.Command("apt", "update")
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr
		if err := updateCmd.Run(); err != nil {
			return fmt.Errorf("apt update failed: %w", err)
		}

		// Install packages
		args := append([]string{"install", "-y"}, packages...)
		installCmd = exec.Command("apt", args...)

	case PackageManagerYum:
		args := append([]string{"install", "-y"}, packages...)
		installCmd = exec.Command("yum", args...)

	case PackageManagerDnf:
		args := append([]string{"install", "-y"}, packages...)
		installCmd = exec.Command("dnf", args...)

	case PackageManagerPacman:
		args := append([]string{"-S", "--noconfirm"}, packages...)
		installCmd = exec.Command("pacman", args...)

	default:
		return fmt.Errorf("unsupported package manager: %s", manager)
	}

	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("%s install failed: %w", manager, err)
	}

	logger.Info("Packages installed successfully", zap.Strings("packages", packages))
	return nil
}

// InstallCephLibraries installs missing Ceph development libraries
// Automatically maps library names to package names for each distro
func InstallCephLibraries(rc *eos_io.RuntimeContext, manager PackageManager, missingLibs []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(missingLibs) == 0 {
		return nil
	}

	logger.Info("Installing missing Ceph development libraries",
		zap.Strings("libraries", missingLibs))

	// Map library names to package names for each distro
	var packages []string

	switch manager {
	case PackageManagerApt:
		// Debian/Ubuntu package names
		pkgMap := map[string]string{
			"librados":  "librados-dev",
			"librbd":    "librbd-dev",
			"libcephfs": "libcephfs-dev",
		}
		for _, lib := range missingLibs {
			if pkg, ok := pkgMap[lib]; ok {
				packages = append(packages, pkg)
			}
		}

	case PackageManagerYum, PackageManagerDnf:
		// RHEL/CentOS/Fedora package names
		pkgMap := map[string]string{
			"librados":  "librados-devel",
			"librbd":    "librbd-devel",
			"libcephfs": "libcephfs-devel",
		}
		for _, lib := range missingLibs {
			if pkg, ok := pkgMap[lib]; ok {
				packages = append(packages, pkg)
			}
		}

	case PackageManagerPacman:
		// Arch Linux - all three libs are in ceph-libs package
		// Deduplicate
		packages = []string{"ceph-libs"}

	default:
		return fmt.Errorf("unsupported package manager: %s", manager)
	}

	if len(packages) == 0 {
		return fmt.Errorf("could not map libraries to packages for %s", manager)
	}

	// Install the packages
	return InstallPackages(rc, manager, packages)
}
