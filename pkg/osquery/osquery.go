// pkg/osquery/osquery.go

package osquery

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallOsquery is the main entry point for osquery installation across platforms
func InstallOsquery(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	start := time.Now()

	// Log platform detection
	osPlat := platform.GetOSPlatform()
	arch := platform.GetArch()
	logger.Info("🔍 Detecting platform for osquery installation",
		zap.String("os", osPlat),
		zap.String("arch", arch),
		zap.String("goos", runtime.GOOS),
		zap.String("goarch", runtime.GOARCH))

	// Route to platform-specific installer
	var err error
	switch osPlat {
	case "linux":
		err = installLinux(rc)
	case "macos":
		err = installMacOS(rc)
	case "windows":
		err = installWindows(rc)
	default:
		logger.Error(" Unsupported platform",
			zap.String("platform", osPlat),
			zap.String("troubleshooting", "osquery supports Linux, macOS, and Windows"))
		return fmt.Errorf("unsupported platform: %s", osPlat)
	}

	if err != nil {
		logger.Error(" osquery installation failed",
			zap.Error(err),
			zap.String("platform", osPlat),
			zap.Duration("duration", time.Since(start)),
			zap.String("troubleshooting", "Check platform-specific requirements and permissions"))
		return err
	}

	// Log successful completion
	logger.Info("✨ osquery installation completed successfully",
		zap.String("platform", osPlat),
		zap.Duration("total_duration", time.Since(start)))

	return nil
}

// GetOsqueryConfig returns the default osquery configuration
func GetOsqueryConfig() string {
	return defaultOsqueryConfig
}

// IsOsqueryInstalled checks if osquery is already installed on the system
func IsOsqueryInstalled(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)

	// Primary check: osqueryi interactive shell (available on all platforms)
	if platform.IsCommandAvailable("osqueryi") {
		logger.Info(" osquery is already installed",
			zap.String("binary", "osqueryi"))
		return true
	}

	// Secondary check: osqueryd daemon binary
	if platform.IsCommandAvailable("osqueryd") {
		logger.Info(" osquery is already installed",
			zap.String("binary", "osqueryd"))
		return true
	}

	// Platform-specific checks
	switch platform.GetOSPlatform() {
	case "windows":
		// Check Windows service
		if platform.IsProcessRunning("osqueryd") {
			logger.Info(" osquery service is running on Windows")
			return true
		}
	case "macos":
		// For macOS, also check Homebrew installation (both cask and formula)
		if platform.IsCommandAvailable("brew") {
			// Check if osquery is installed via Homebrew cask (most common)
			caskOutput, caskErr := execute.Run(rc.Ctx, execute.Options{
				Command: "brew",
				Args:    []string{"list", "--cask", "osquery"},
			})
			if caskErr == nil && strings.Contains(caskOutput, "osquery") {
				logger.Info(" osquery is installed via Homebrew (cask)")
				return true
			}

			// Check if osquery is installed via Homebrew formula (alternative)
			formulaOutput, formulaErr := execute.Run(rc.Ctx, execute.Options{
				Command: "brew",
				Args:    []string{"list", "--formula", "osquery"},
			})
			if formulaErr == nil && strings.Contains(formulaOutput, "osquery") {
				logger.Info(" osquery is installed via Homebrew (formula)")
				return true
			}
		}
		// Check macOS launchd (for non-Homebrew installations)
		if platform.IsProcessRunning("com.facebook.osqueryd") {
			logger.Info(" osquery is managed by launchd on macOS")
			return true
		}
	case "linux":
		// Check systemd service
		if platform.IsProcessRunning("osqueryd") {
			logger.Info(" osquery service is running on Linux")
			return true
		}
	}

	logger.Info(" osquery is not installed")
	return false
}

// VerifyOsqueryInstallation performs post-installation verification
func VerifyOsqueryInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying osquery installation")

	// Check if osqueryi (interactive shell) is available
	if !platform.IsCommandAvailable("osqueryi") {
		logger.Error(" osqueryi binary not found",
			zap.String("troubleshooting", "Ensure osquery installation completed successfully"))
		return fmt.Errorf("osqueryi binary not found in PATH")
	}

	// Platform-specific verification
	switch platform.GetOSPlatform() {
	case "linux":
		return verifyLinuxInstallation(rc)
	case "macos":
		return verifyMacOSInstallation(rc)
	case "windows":
		return verifyWindowsInstallation(rc)
	default:
		return fmt.Errorf("unsupported platform for verification")
	}
}

// GetOsqueryPaths returns platform-specific paths for osquery
func GetOsqueryPaths() OsqueryPaths {
	switch platform.GetOSPlatform() {
	case "windows":
		return OsqueryPaths{
			ConfigPath:   `C:\Program Files\osquery\osquery.conf`,
			LogPath:      `C:\Program Files\osquery\log`,
			DatabasePath: `C:\Program Files\osquery\osquery.db`,
			ServiceName:  "osqueryd",
		}
	case "macos":
		return OsqueryPaths{
			ConfigPath:   "/var/osquery/osquery.conf",
			LogPath:      "/var/log/osquery",
			DatabasePath: "/var/osquery/osquery.db",
			ServiceName:  "com.facebook.osqueryd",
		}
	default: // Linux
		return OsqueryPaths{
			ConfigPath:   "/etc/osquery/osquery.conf",
			LogPath:      "/var/log/osquery",
			DatabasePath: "/var/osquery/osquery.db",
			ServiceName:  "osqueryd",
		}
	}
}
