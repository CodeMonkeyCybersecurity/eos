// pkg/build/dependencies.go
//
// Build dependency verification - checks for required tools and libraries
// Pure business logic for verifying build prerequisites

package build

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DependencyCheckResult contains results of build dependency verification
type DependencyCheckResult struct {
	GoPath         string   // Path to Go compiler
	GoVersion      string   // Go version string
	PkgConfigPath  string   // Path to pkg-config
	LibvirtOK      bool     // Libvirt dev libraries found
	CephLibsOK     bool     // All Ceph dev libraries found
	MissingCephLibs []string // List of missing Ceph libraries
}

// CephLibrary represents a Ceph development library
type CephLibrary struct {
	Name       string // pkg-config name (e.g., "librados")
	HeaderPath string // Header file path (e.g., "/usr/include/rados/librados.h")
	DebianPkg  string // Debian/Ubuntu package name
	RHELPkg    string // RHEL/CentOS/Fedora package name
}

var (
	// CephLibraries defines the required Ceph development libraries
	CephLibraries = []CephLibrary{
		{
			Name:       "librados",
			HeaderPath: "/usr/include/rados/librados.h",
			DebianPkg:  "librados-dev",
			RHELPkg:    "librados-devel",
		},
		{
			Name:       "librbd",
			HeaderPath: "/usr/include/rbd/librbd.h",
			DebianPkg:  "librbd-dev",
			RHELPkg:    "librbd-devel",
		},
		{
			Name:       "libcephfs",
			HeaderPath: "/usr/include/cephfs/libcephfs.h",
			DebianPkg:  "libcephfs-dev",
			RHELPkg:    "libcephfs-devel",
		},
	}
)

// VerifyAllDependencies checks all required build dependencies
// Returns detailed results of what was found/missing
func VerifyAllDependencies(rc *eos_io.RuntimeContext) (*DependencyCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying build dependencies")

	result := &DependencyCheckResult{}

	// 1. Verify Go compiler
	goPath, goVersion, err := VerifyGoCompiler(rc)
	if err != nil {
		return nil, fmt.Errorf("Go compiler not available: %w", err)
	}
	result.GoPath = goPath
	result.GoVersion = goVersion
	logger.Debug("Go compiler found",
		zap.String("path", goPath),
		zap.String("version", goVersion))

	// 2. Verify pkg-config (required for library checks)
	pkgConfigPath, err := exec.LookPath("pkg-config")
	if err != nil {
		return nil, fmt.Errorf("pkg-config not found - required for library detection: %w", err)
	}
	result.PkgConfigPath = pkgConfigPath
	logger.Debug("pkg-config found", zap.String("path", pkgConfigPath))

	// 3. Verify libvirt development libraries
	if err := VerifyLibvirtDev(rc, pkgConfigPath); err != nil {
		return nil, fmt.Errorf("libvirt development libraries not available: %w", err)
	}
	result.LibvirtOK = true
	logger.Debug("Libvirt development libraries found")

	// 4. Verify Ceph development libraries
	missingCephLibs, err := VerifyCephDev(rc, pkgConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to check Ceph libraries: %w", err)
	}
	result.MissingCephLibs = missingCephLibs
	result.CephLibsOK = len(missingCephLibs) == 0

	if result.CephLibsOK {
		logger.Debug("All Ceph development libraries found")
	} else {
		logger.Debug("Missing Ceph development libraries",
			zap.Strings("missing", missingCephLibs))
	}

	logger.Info("Build dependencies verified successfully")
	return result, nil
}

// VerifyGoCompiler finds and verifies the Go compiler
// Returns: goPath, goVersion, error
func VerifyGoCompiler(rc *eos_io.RuntimeContext) (string, string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check PATH first
	goPath, err := exec.LookPath("go")
	if err != nil {
		// Not in PATH - check standard installation locations
		standardLocations := []string{
			"/usr/local/go/bin/go",
			filepath.Join(os.Getenv("HOME"), "go", "bin", "go"),
		}

		for _, loc := range standardLocations {
			if _, err := os.Stat(loc); err == nil {
				goPath = loc
				logger.Debug("Go found at standard location", zap.String("path", loc))
				break
			}
		}

		if goPath == "" {
			return "", "", fmt.Errorf("go compiler not found in PATH or standard locations")
		}
	}

	// Get Go version
	goVersionCmd := exec.Command(goPath, "version")
	goVersionOutput, err := goVersionCmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to check go version at %s: %w\nOutput: %s",
			goPath, err, strings.TrimSpace(string(goVersionOutput)))
	}

	goVersion := strings.TrimSpace(string(goVersionOutput))
	return goPath, goVersion, nil
}

// VerifyLibvirtDev checks for libvirt development libraries
func VerifyLibvirtDev(rc *eos_io.RuntimeContext, pkgConfigPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	libvirtCheck := exec.Command(pkgConfigPath, "--exists", "libvirt")
	libvirtOutput, err := libvirtCheck.CombinedOutput()
	if err != nil {
		logger.Debug("libvirt pkg-config check failed",
			zap.Error(err),
			zap.String("output", strings.TrimSpace(string(libvirtOutput))))
		return fmt.Errorf("libvirt development libraries not found\n"+
			"Fix: Install libvirt development libraries:\n"+
			"  Ubuntu/Debian: sudo apt install libvirt-dev\n"+
			"  RHEL/CentOS:   sudo yum install libvirt-devel\n"+
			"  Fedora:        sudo dnf install libvirt-devel")
	}

	return nil
}

// VerifyCephDev checks for Ceph development libraries
// Returns list of missing library names (empty if all found)
// NOTE: Ubuntu Ceph packages don't provide .pc files, so we check headers as fallback
func VerifyCephDev(rc *eos_io.RuntimeContext, pkgConfigPath string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	var missingLibs []string

	for _, lib := range CephLibraries {
		// First try pkg-config (works on some distros like Fedora/RHEL)
		cephCheck := exec.Command(pkgConfigPath, "--exists", lib.Name)
		if err := cephCheck.Run(); err != nil {
			// pkg-config failed, check for header file directly
			// Ubuntu Ceph packages don't provide .pc files
			if _, err := os.Stat(lib.HeaderPath); os.IsNotExist(err) {
				logger.Debug("Ceph library not found",
					zap.String("library", lib.Name),
					zap.Bool("pkg_config_failed", true),
					zap.String("header_path", lib.HeaderPath),
					zap.Bool("header_exists", false))
				missingLibs = append(missingLibs, lib.Name)
			} else {
				logger.Debug("Ceph library found via header check (pkg-config unavailable)",
					zap.String("library", lib.Name),
					zap.String("header_path", lib.HeaderPath))
			}
		} else {
			logger.Debug("Ceph library found via pkg-config",
				zap.String("library", lib.Name))
		}
	}

	return missingLibs, nil
}

// FormatMissingCephLibsError creates a user-friendly error message for missing Ceph libraries
func FormatMissingCephLibsError(missingLibs []string) string {
	if len(missingLibs) == 0 {
		return ""
	}

	// Build package name lists
	var debianPkgs []string
	var rhelPkgs []string

	for _, libName := range missingLibs {
		for _, lib := range CephLibraries {
			if lib.Name == libName {
				debianPkgs = append(debianPkgs, lib.DebianPkg)
				rhelPkgs = append(rhelPkgs, lib.RHELPkg)
				break
			}
		}
	}

	return fmt.Sprintf("Ceph development libraries not found: %v\n"+
		"Checked: pkg-config and header files in /usr/include/\n"+
		"Fix: Install Ceph development libraries:\n"+
		"  Ubuntu/Debian: sudo apt install %s\n"+
		"  RHEL/CentOS:   sudo yum install %s\n"+
		"  Fedora:        sudo dnf install %s",
		missingLibs,
		strings.Join(debianPkgs, " "),
		strings.Join(rhelPkgs, " "),
		strings.Join(rhelPkgs, " "))
}
