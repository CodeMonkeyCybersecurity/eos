// pkg/build/dependency_installer.go
//
// Human-centric dependency installation with informed consent
// Guides users through installing missing build dependencies

package build

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// DependencyInstallResult tracks what was installed
type DependencyInstallResult struct {
	GitInstalled       bool
	PkgConfigInstalled bool
	LibvirtInstalled   bool
	CephLibsInstalled  bool
	Packages           []string // List of packages that were installed
}

// CheckAndInstallDependenciesWithConsent checks all build dependencies
// and offers to install missing ones with user consent
// HUMAN-CENTRIC: Never fails immediately - always offers guidance
func CheckAndInstallDependenciesWithConsent(rc *eos_io.RuntimeContext) (*DependencyInstallResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	result := &DependencyInstallResult{}

	logger.Info("Checking build dependencies")

	// Check if we're in an interactive terminal
	isInteractive := term.IsTerminal(int(os.Stdin.Fd()))

	// Step 1: Check Git availability
	if err := checkGitWithGuidance(rc, result, isInteractive); err != nil {
		return result, err
	}

	// Step 2: Check Go compiler (already handled by VerifyAllDependencies)
	depResult, err := VerifyAllDependencies(rc)
	if err != nil {
		// Go compiler missing - this is critical
		return result, fmt.Errorf("Go compiler not found: %w\n\n"+
			"Eos requires Go 1.21 or later to build.\n\n"+
			"Install Go:\n"+
			"  Ubuntu/Debian: sudo snap install go --classic\n"+
			"  Or download from: https://go.dev/dl/\n\n"+
			"After installing, re-run: eos self update", err)
	}

	// Step 3: Check pkg-config
	if err := checkPkgConfigWithGuidance(rc, result, isInteractive); err != nil {
		return result, err
	}

	// Step 4: Check libvirt development libraries
	if err := checkLibvirtWithGuidance(rc, depResult.PkgConfigPath, result, isInteractive); err != nil {
		return result, err
	}

	// Step 5: Check Ceph development libraries
	if !depResult.CephLibsOK {
		if err := checkCephLibsWithGuidance(rc, depResult.MissingCephLibs, result, isInteractive); err != nil {
			return result, err
		}
	}

	logger.Info("All build dependencies satisfied",
		zap.Int("packages_installed", len(result.Packages)))

	return result, nil
}

// checkGitWithGuidance checks if git is available and offers to install if missing
func checkGitWithGuidance(rc *eos_io.RuntimeContext, result *DependencyInstallResult, isInteractive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if git is available
	if _, err := interaction.CheckDependencyInstalled("git"); err == nil {
		logger.Debug("Git is available")
		return nil
	}

	// Git is missing
	logger.Warn("Git is not installed")

	pkgMgr := system.DetectPackageManager()
	if pkgMgr == system.PackageManagerNone {
		return fmt.Errorf("Git is required but not installed, and no supported package manager found.\n\n" +
			"Eos requires Git to pull updates from GitHub.\n\n" +
			"Install Git manually:\n" +
			"  Ubuntu/Debian: sudo apt install git\n" +
			"  RHEL/CentOS:   sudo yum install git\n" +
			"  Fedora:        sudo dnf install git\n\n" +
			"After installing, re-run: eos self update")
	}

	// Offer to install Git
	if !isInteractive {
		return fmt.Errorf("Git is required but not installed (non-interactive mode).\n\n"+
			"Install Git:\n"+
			"  %s\n\n"+
			"After installing, re-run: eos self update",
			getGitInstallCommand(pkgMgr))
	}

	// Interactive mode - ask for consent
	config := interaction.DependencyConfig{
		Name:         "Git",
		Description:  "Version control system required to pull eos updates from GitHub",
		CheckCommand: "git",
		CheckArgs:    []string{"--version"},
		InstallCmd:   getGitInstallCommand(pkgMgr),
		Required:     true,
		AutoInstall:  true, // Offer to auto-install with user consent
	}

	depResult, err := interaction.CheckDependencyWithPrompt(rc, config)
	if err != nil {
		return err
	}

	if depResult.Found {
		result.GitInstalled = true
		result.Packages = append(result.Packages, "git")
		logger.Info("Git installed successfully")
	} else if depResult.UserDecline {
		return fmt.Errorf("Git is required but user declined installation")
	}

	return nil
}

// checkPkgConfigWithGuidance checks if pkg-config is available
func checkPkgConfigWithGuidance(rc *eos_io.RuntimeContext, result *DependencyInstallResult, isInteractive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if pkg-config is available
	if _, err := interaction.CheckDependencyInstalled("pkg-config"); err == nil {
		logger.Debug("pkg-config is available")
		return nil
	}

	// pkg-config is missing
	logger.Warn("pkg-config is not installed")

	pkgMgr := system.DetectPackageManager()
	if pkgMgr == system.PackageManagerNone {
		return fmt.Errorf("pkg-config is required but not installed.\n\n" +
			"pkg-config is used to detect C library headers (libvirt, ceph).\n\n" +
			"Install pkg-config manually:\n" +
			"  Ubuntu/Debian: sudo apt install pkg-config\n" +
			"  RHEL/CentOS:   sudo yum install pkgconfig\n" +
			"  Fedora:        sudo dnf install pkgconfig\n\n" +
			"After installing, re-run: eos self update")
	}

	// Offer to install pkg-config
	if !isInteractive {
		return fmt.Errorf("pkg-config is required but not installed (non-interactive mode).\n\n"+
			"Install pkg-config:\n"+
			"  %s\n\n"+
			"After installing, re-run: eos self update",
			getPkgConfigInstallCommand(pkgMgr))
	}

	// Interactive mode - ask for consent
	config := interaction.DependencyConfig{
		Name:         "pkg-config",
		Description:  "Build tool used to detect C library headers (libvirt, ceph)",
		CheckCommand: "pkg-config",
		CheckArgs:    []string{"--version"},
		InstallCmd:   getPkgConfigInstallCommand(pkgMgr),
		Required:     true,
		AutoInstall:  true, // Offer to auto-install with user consent
	}

	depResult, err := interaction.CheckDependencyWithPrompt(rc, config)
	if err != nil {
		return err
	}

	if depResult.Found {
		result.PkgConfigInstalled = true
		result.Packages = append(result.Packages, "pkg-config")
		logger.Info("pkg-config installed successfully")
	} else if depResult.UserDecline {
		return fmt.Errorf("pkg-config is required but user declined installation")
	}

	return nil
}

// checkLibvirtWithGuidance checks if libvirt development libraries are available
func checkLibvirtWithGuidance(rc *eos_io.RuntimeContext, pkgConfigPath string, result *DependencyInstallResult, isInteractive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if libvirt-dev is available
	if err := VerifyLibvirtDev(rc, pkgConfigPath); err == nil {
		logger.Debug("libvirt development libraries are available")
		return nil
	}

	// libvirt-dev is missing
	logger.Warn("libvirt development libraries not found")

	pkgMgr := system.DetectPackageManager()
	if pkgMgr == system.PackageManagerNone {
		return fmt.Errorf("libvirt development libraries are required but not installed.\n\n" +
			"Eos uses libvirt to manage virtual machines (KVM).\n\n" +
			"Install libvirt development libraries manually:\n" +
			"  Ubuntu/Debian: sudo apt install libvirt-dev\n" +
			"  RHEL/CentOS:   sudo yum install libvirt-devel\n" +
			"  Fedora:        sudo dnf install libvirt-devel\n\n" +
			"After installing, re-run: eos self update")
	}

	// Offer to install libvirt-dev
	if !isInteractive {
		return fmt.Errorf("libvirt development libraries are required but not installed (non-interactive mode).\n\n"+
			"Install libvirt-dev:\n"+
			"  %s\n\n"+
			"After installing, re-run: eos self update",
			getLibvirtDevInstallCommand(pkgMgr))
	}

	// Interactive mode - ask for consent
	config := interaction.DependencyConfig{
		Name:         "libvirt-dev",
		Description:  "Development headers for libvirt (KVM/QEMU virtual machine management)",
		CheckCommand: "pkg-config",
		CheckArgs:    []string{"--exists", "libvirt"},
		InstallCmd:   getLibvirtDevInstallCommand(pkgMgr),
		Required:     true,
		AutoInstall:  true, // Offer to auto-install with user consent
	}

	depResult, err := interaction.CheckDependencyWithPrompt(rc, config)
	if err != nil {
		return err
	}

	if depResult.Found {
		result.LibvirtInstalled = true
		result.Packages = append(result.Packages, getLibvirtDevPackageName(pkgMgr))
		logger.Info("libvirt development libraries installed successfully")
	} else if depResult.UserDecline {
		return fmt.Errorf("libvirt-dev is required but user declined installation")
	}

	return nil
}

// checkCephLibsWithGuidance checks if Ceph development libraries are available
func checkCephLibsWithGuidance(rc *eos_io.RuntimeContext, missingLibs []string, result *DependencyInstallResult, isInteractive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(missingLibs) == 0 {
		return nil
	}

	logger.Warn("Ceph development libraries not found",
		zap.Strings("missing", missingLibs))

	pkgMgr := system.DetectPackageManager()
	if pkgMgr == system.PackageManagerNone {
		return fmt.Errorf("%s\n\n"+
			"No supported package manager found for auto-install.\n"+
			"Please install Ceph libraries manually.",
			FormatMissingCephLibsError(missingLibs))
	}

	// Get pkgConfigPath for use in check function
	verifyResult, err := VerifyAllDependencies(rc)
	if err != nil {
		return fmt.Errorf("failed to verify dependencies: %w", err)
	}
	pkgConfigPath := verifyResult.PkgConfigPath

	// Build list of package names
	packages := getCephPackageNames(pkgMgr, missingLibs)

	// Offer to install Ceph libraries
	if !isInteractive {
		return fmt.Errorf("Ceph development libraries are required but not installed (non-interactive mode).\n\n"+
			"Missing libraries: %v\n\n"+
			"Install Ceph libraries:\n"+
			"  %s\n\n"+
			"After installing, re-run: eos self update",
			missingLibs,
			getCephInstallCommand(pkgMgr, packages))
	}

	// Interactive mode - ask for consent
	config := interaction.DependencyConfig{
		Name:        "Ceph development libraries",
		Description: fmt.Sprintf("Development headers for Ceph storage (%s)", strings.Join(missingLibs, ", ")),
		// Use custom check function that verifies all Ceph libs
		CustomCheckFn: func(ctx context.Context) error {
			// Re-check after potential installation
			stillMissing, err := VerifyCephDev(rc, pkgConfigPath)
			if err != nil {
				return err
			}
			if len(stillMissing) > 0 {
				return fmt.Errorf("still missing: %v", stillMissing)
			}
			return nil
		},
		InstallCmd:  getCephInstallCommand(pkgMgr, packages),
		Required:    true,
		AutoInstall: true, // Offer to auto-install with user consent
	}

	depResult, err := interaction.CheckDependencyWithPrompt(rc, config)
	if err != nil {
		return err
	}

	if depResult.Found {
		result.CephLibsInstalled = true
		result.Packages = append(result.Packages, packages...)
		logger.Info("Ceph development libraries installed successfully")
	} else if depResult.UserDecline {
		return fmt.Errorf("Ceph libraries are required but user declined installation")
	}

	return nil
}

// Helper functions to generate install commands

func getGitInstallCommand(pkgMgr system.PackageManager) string {
	switch pkgMgr {
	case system.PackageManagerApt:
		return "sudo apt update && sudo apt install -y git"
	case system.PackageManagerYum:
		return "sudo yum install -y git"
	case system.PackageManagerDnf:
		return "sudo dnf install -y git"
	case system.PackageManagerPacman:
		return "sudo pacman -S --noconfirm git"
	default:
		return "# No package manager detected"
	}
}

func getPkgConfigInstallCommand(pkgMgr system.PackageManager) string {
	switch pkgMgr {
	case system.PackageManagerApt:
		return "sudo apt update && sudo apt install -y pkg-config"
	case system.PackageManagerYum:
		return "sudo yum install -y pkgconfig"
	case system.PackageManagerDnf:
		return "sudo dnf install -y pkgconfig"
	case system.PackageManagerPacman:
		return "sudo pacman -S --noconfirm pkgconf"
	default:
		return "# No package manager detected"
	}
}

func getLibvirtDevInstallCommand(pkgMgr system.PackageManager) string {
	switch pkgMgr {
	case system.PackageManagerApt:
		return "sudo apt update && sudo apt install -y libvirt-dev"
	case system.PackageManagerYum:
		return "sudo yum install -y libvirt-devel"
	case system.PackageManagerDnf:
		return "sudo dnf install -y libvirt-devel"
	case system.PackageManagerPacman:
		return "sudo pacman -S --noconfirm libvirt"
	default:
		return "# No package manager detected"
	}
}

func getLibvirtDevPackageName(pkgMgr system.PackageManager) string {
	switch pkgMgr {
	case system.PackageManagerApt:
		return "libvirt-dev"
	case system.PackageManagerYum, system.PackageManagerDnf:
		return "libvirt-devel"
	case system.PackageManagerPacman:
		return "libvirt"
	default:
		return "libvirt-dev"
	}
}

func getCephPackageNames(pkgMgr system.PackageManager, missingLibs []string) []string {
	packages := []string{}

	for _, lib := range missingLibs {
		var pkgName string
		switch pkgMgr {
		case system.PackageManagerApt:
			// Debian/Ubuntu package names
			switch lib {
			case "librados":
				pkgName = "librados-dev"
			case "librbd":
				pkgName = "librbd-dev"
			case "libcephfs":
				pkgName = "libcephfs-dev"
			}
		case system.PackageManagerYum, system.PackageManagerDnf:
			// RHEL/CentOS/Fedora package names
			switch lib {
			case "librados":
				pkgName = "librados-devel"
			case "librbd":
				pkgName = "librbd-devel"
			case "libcephfs":
				pkgName = "libcephfs-devel"
			}
		case system.PackageManagerPacman:
			// Arch Linux - all in ceph-libs
			pkgName = "ceph-libs"
		}

		if pkgName != "" && !contains(packages, pkgName) {
			packages = append(packages, pkgName)
		}
	}

	return packages
}

func getCephInstallCommand(pkgMgr system.PackageManager, packages []string) string {
	switch pkgMgr {
	case system.PackageManagerApt:
		return fmt.Sprintf("sudo apt update && sudo apt install -y %s", strings.Join(packages, " "))
	case system.PackageManagerYum:
		return fmt.Sprintf("sudo yum install -y %s", strings.Join(packages, " "))
	case system.PackageManagerDnf:
		return fmt.Sprintf("sudo dnf install -y %s", strings.Join(packages, " "))
	case system.PackageManagerPacman:
		return fmt.Sprintf("sudo pacman -S --noconfirm %s", strings.Join(packages, " "))
	default:
		return "# No package manager detected"
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
