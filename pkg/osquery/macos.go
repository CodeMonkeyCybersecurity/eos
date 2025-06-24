// pkg/osquery/macos.go

package osquery

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installMacOS handles osquery installation on macOS
func installMacOS(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("🍎 Installing osquery on macOS")

	// Check if running as root - Homebrew doesn't support root execution
	if os.Getuid() == 0 {
		logger.Info("🔒 Running as root - using PKG installer (Homebrew doesn't support root)")
		return installMacOSPKG(rc)
	}

	// Check if Homebrew is available for non-root users
	if platform.IsCommandAvailable("brew") {
		logger.Info("🍺 Using Homebrew to install osquery")
		err := installMacOSBrew(rc)
		if err != nil {
			logger.Warn("⚠️ Homebrew installation failed, falling back to PKG installer",
				zap.Error(err))
			return installMacOSPKG(rc)
		}
		return nil
	}

	// Fall back to PKG installer
	logger.Info("📦 Using PKG installer for osquery")
	return installMacOSPKG(rc)
}

// installMacOSBrew installs osquery using Homebrew
func installMacOSBrew(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Update Homebrew
	logger.Info("🔄 Updating Homebrew")
	if err := execute.RunSimple(rc.Ctx, "brew", "update"); err != nil {
		logger.Warn("⚠️ Failed to update Homebrew",
			zap.Error(err),
			zap.String("note", "Continuing with installation"))
	}

	// Install osquery
	logger.Info("📦 Installing osquery via Homebrew")
	if err := execute.RunSimple(rc.Ctx, "brew", "install", "osquery"); err != nil {
		logger.Error("❌ Failed to install osquery via Homebrew",
			zap.Error(err),
			zap.String("troubleshooting", "Try 'brew doctor' to diagnose Homebrew issues"))
		return fmt.Errorf("brew install osquery: %w", err)
	}

	// Configure osquery
	if err := configureMacOSService(rc); err != nil {
		return err
	}

	logger.Info("✅ osquery installed successfully via Homebrew")
	return nil
}

// installMacOSPKG installs osquery using the official PKG installer
func installMacOSPKG(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Determine package URL based on architecture
	arch := platform.GetArch()
	var pkgURL string
	switch arch {
	case "amd64":
		pkgURL = "https://pkg.osquery.io/darwin/osquery-5.10.2.pkg"
	case "arm64":
		pkgURL = "https://pkg.osquery.io/darwin/osquery-5.10.2-arm64.pkg"
	default:
		logger.Error("❌ Unsupported macOS architecture",
			zap.String("arch", arch))
		return fmt.Errorf("unsupported architecture: %s", arch)
	}

	// Download package
	logger.Info("📥 Downloading osquery package",
		zap.String("url", pkgURL),
		zap.String("arch", arch))
	
	pkgPath := "/tmp/osquery.pkg"
	if err := execute.RunSimple(rc.Ctx, "curl", "-fsSL", pkgURL, "-o", pkgPath); err != nil {
		logger.Error("❌ Failed to download osquery package",
			zap.Error(err),
			zap.String("url", pkgURL),
			zap.String("troubleshooting", "Check internet connectivity and URL validity"))
		return fmt.Errorf("download osquery package: %w", err)
	}
	defer func() {
		if err := os.Remove(pkgPath); err != nil {
			logger.Warn("⚠️ Failed to remove temporary package file",
				zap.String("path", pkgPath),
				zap.Error(err))
		}
	}()

	// Install package
	logger.Info("🔧 Installing osquery package")
	if err := execute.RunSimple(rc.Ctx, "sudo", "installer", "-pkg", pkgPath, "-target", "/"); err != nil {
		logger.Error("❌ Failed to install osquery package",
			zap.Error(err),
			zap.String("troubleshooting", "Ensure you have administrator privileges"))
		return fmt.Errorf("install osquery package: %w", err)
	}

	// Configure osquery
	if err := configureMacOSService(rc); err != nil {
		return err
	}

	logger.Info("✅ osquery installed successfully via PKG installer")
	return nil
}

// configureMacOSService configures osquery on macOS
func configureMacOSService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	paths := GetOsqueryPaths()

	// Create configuration directory
	configDir := "/var/osquery"
	logger.Info("📁 Creating configuration directory",
		zap.String("path", configDir))
	if err := execute.RunSimple(rc.Ctx, "sudo", "mkdir", "-p", configDir); err != nil {
		logger.Error("❌ Failed to create config directory",
			zap.Error(err),
			zap.String("path", configDir))
		return fmt.Errorf("create config directory: %w", err)
	}

	// Write configuration
	logger.Info("📝 Writing osquery configuration",
		zap.String("path", paths.ConfigPath))
	configContent := defaultOsqueryConfig
	if err := os.WriteFile("/tmp/osquery.conf", []byte(configContent), 0644); err != nil {
		logger.Error("❌ Failed to write temporary config",
			zap.Error(err))
		return fmt.Errorf("write temporary config: %w", err)
	}
	
	if err := execute.RunSimple(rc.Ctx, "sudo", "cp", "/tmp/osquery.conf", paths.ConfigPath); err != nil {
		logger.Error("❌ Failed to copy configuration",
			zap.Error(err),
			zap.String("path", paths.ConfigPath))
		return fmt.Errorf("copy configuration: %w", err)
	}
	if err := os.Remove("/tmp/osquery.conf"); err != nil {
		logger.Warn("⚠️ Failed to remove temporary config file",
			zap.String("path", "/tmp/osquery.conf"),
			zap.Error(err))
	}

	// Load and start the LaunchDaemon
	logger.Info("🚀 Loading osquery LaunchDaemon")
	plistPath := "/Library/LaunchDaemons/com.facebook.osqueryd.plist"
	
	// Unload if already loaded
	if err := execute.RunSimple(rc.Ctx, "sudo", "launchctl", "unload", plistPath); err != nil {
		logger.Debug("🔄 Service was not previously loaded", zap.Error(err))
	}
	
	// Load the daemon
	if err := execute.RunSimple(rc.Ctx, "sudo", "launchctl", "load", "-w", plistPath); err != nil {
		logger.Warn("⚠️ Failed to load osquery LaunchDaemon",
			zap.Error(err),
			zap.String("note", "Service may need manual configuration"))
	}

	return nil
}

// verifyMacOSInstallation verifies osquery installation on macOS
func verifyMacOSInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying osquery installation on macOS")

	// Check if osqueryi is available
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "osqueryi",
		Args:    []string{"--version"},
	})
	if err != nil {
		logger.Error("❌ osqueryi not found or not working",
			zap.Error(err))
		return fmt.Errorf("osqueryi verification failed: %w", err)
	}

	logger.Info("✅ osquery verified successfully",
		zap.String("version", output))

	// Check if service is running
	if err := execute.RunSimple(rc.Ctx, "sudo", "launchctl", "list", "com.facebook.osqueryd"); err != nil {
		logger.Warn("⚠️ osquery service not running",
			zap.Error(err),
			zap.String("note", "Service may need manual start"))
	} else {
		logger.Info("✅ osquery service is running")
	}

	return nil
}