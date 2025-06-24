// pkg/osquery/windows.go

package osquery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installWindows handles osquery installation on Windows
func installWindows(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("🪟 Installing osquery on Windows")

	// Check if Chocolatey is available
	if platform.IsCommandAvailable("choco") {
		logger.Info("🍫 Using Chocolatey to install osquery")
		return installWindowsChocolatey(rc)
	}

	// Fall back to MSI installer
	logger.Info("📦 Using MSI installer for osquery")
	return installWindowsMSI(rc)
}

// installWindowsChocolatey installs osquery using Chocolatey
func installWindowsChocolatey(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Install osquery via Chocolatey
	logger.Info("📦 Installing osquery via Chocolatey")
	if err := execute.RunSimple(rc.Ctx, "choco", "install", "osquery", "-y", "--no-progress"); err != nil {
		logger.Error("❌ Failed to install osquery via Chocolatey",
			zap.Error(err),
			zap.String("troubleshooting", "Ensure Chocolatey is properly installed and you have administrator privileges"))
		return fmt.Errorf("choco install osquery: %w", err)
	}

	// Configure osquery
	if err := configureWindowsService(rc); err != nil {
		return err
	}

	logger.Info("✅ osquery installed successfully via Chocolatey")
	return nil
}

// installWindowsMSI installs osquery using the official MSI installer
func installWindowsMSI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Determine MSI URL based on architecture
	arch := platform.GetArch()
	var msiURL string
	switch arch {
	case "amd64":
		msiURL = "https://pkg.osquery.io/windows/osquery-5.10.2.msi"
	default:
		logger.Error("❌ Unsupported Windows architecture",
			zap.String("arch", arch))
		return fmt.Errorf("unsupported architecture: %s", arch)
	}

	// Download MSI
	logger.Info("📥 Downloading osquery MSI installer",
		zap.String("url", msiURL))
	
	tempDir := os.TempDir()
	msiPath := filepath.Join(tempDir, "osquery.msi")
	
	// Use PowerShell to download the file
	downloadCmd := fmt.Sprintf("(New-Object System.Net.WebClient).DownloadFile('%s', '%s')", msiURL, msiPath)
	if err := execute.RunSimple(rc.Ctx, "powershell", "-Command", downloadCmd); err != nil {
		logger.Error("❌ Failed to download osquery MSI",
			zap.Error(err),
			zap.String("url", msiURL),
			zap.String("troubleshooting", "Check internet connectivity and Windows Defender settings"))
		return fmt.Errorf("download osquery MSI: %w", err)
	}
	defer func() {
		if err := os.Remove(msiPath); err != nil {
			logger.Warn("⚠️ Failed to remove temporary MSI file",
				zap.String("path", msiPath),
				zap.Error(err))
		}
	}()

	// Install MSI
	logger.Info("🔧 Installing osquery from MSI")
	if err := execute.RunSimple(rc.Ctx, "msiexec", "/i", msiPath, "/quiet", "/norestart"); err != nil {
		logger.Error("❌ Failed to install osquery MSI",
			zap.Error(err),
			zap.String("troubleshooting", "Ensure you have administrator privileges and Windows Installer service is running"))
		return fmt.Errorf("install osquery MSI: %w", err)
	}

	// Wait for installation to complete
	logger.Info("⏳ Waiting for installation to complete")
	time.Sleep(10 * time.Second)

	// Configure osquery
	if err := configureWindowsService(rc); err != nil {
		return err
	}

	logger.Info("✅ osquery installed successfully via MSI installer")
	return nil
}

// configureWindowsService configures osquery service on Windows
func configureWindowsService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	paths := GetOsqueryPaths()

	// Create configuration directory if it doesn't exist
	configDir := filepath.Dir(paths.ConfigPath)
	logger.Info("📁 Creating configuration directory",
		zap.String("path", configDir))
	if err := os.MkdirAll(configDir, 0755); err != nil {
		logger.Error("❌ Failed to create config directory",
			zap.Error(err),
			zap.String("path", configDir))
		return fmt.Errorf("create config directory: %w", err)
	}

	// Write Windows-specific configuration
	logger.Info("📝 Writing osquery configuration",
		zap.String("path", paths.ConfigPath))
	configContent := GetWindowsConfig()
	if err := os.WriteFile(paths.ConfigPath, []byte(configContent), 0644); err != nil {
		logger.Error("❌ Failed to write configuration",
			zap.Error(err),
			zap.String("path", paths.ConfigPath))
		return fmt.Errorf("write configuration: %w", err)
	}

	// Stop service if running
	logger.Info("🛑 Stopping osquery service if running")
	if err := execute.RunSimple(rc.Ctx, "sc", "stop", "osqueryd"); err != nil {
		logger.Debug("🔄 Service was not running", zap.Error(err))
	}
	time.Sleep(2 * time.Second)

	// Configure service to start automatically
	logger.Info("⚙️ Configuring osquery service")
	if err := execute.RunSimple(rc.Ctx, "sc", "config", "osqueryd", "start=", "auto"); err != nil {
		logger.Warn("⚠️ Failed to configure service startup",
			zap.Error(err),
			zap.String("note", "Service may need manual configuration"))
	}

	// Start the service
	logger.Info("🚀 Starting osquery service")
	if err := execute.RunSimple(rc.Ctx, "sc", "start", "osqueryd"); err != nil {
		logger.Warn("⚠️ Failed to start osquery service",
			zap.Error(err),
			zap.String("note", "Service may need manual start"))
		
		// Try using net start as alternative
		if err := execute.RunSimple(rc.Ctx, "net", "start", "osqueryd"); err != nil {
			logger.Error("❌ Failed to start service with net start",
				zap.Error(err))
		}
	}

	return nil
}

// verifyWindowsInstallation verifies osquery installation on Windows
func verifyWindowsInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying osquery installation on Windows")

	// Check if osqueryi.exe is available
	osqueryiPath := `C:\Program Files\osquery\osqueryi.exe`
	if _, err := os.Stat(osqueryiPath); err != nil {
		logger.Error("❌ osqueryi.exe not found",
			zap.String("path", osqueryiPath),
			zap.Error(err))
		return fmt.Errorf("osqueryi.exe not found: %w", err)
	}

	// Run version check
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: osqueryiPath,
		Args:    []string{"--version"},
	})
	if err != nil {
		logger.Error("❌ Failed to run osqueryi",
			zap.Error(err))
		return fmt.Errorf("osqueryi verification failed: %w", err)
	}

	// Clean up the version output and extract version number
	version := strings.TrimSpace(output)
	if version != "" {
		// Extract version from "osqueryi version X.X.X" format
		parts := strings.Fields(version)
		if len(parts) >= 3 && parts[1] == "version" {
			version = parts[2]
		}
	}
	
	logger.Info("✅ osquery verified successfully",
		zap.String("version", version))

	// Check service status
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "sc",
		Args:    []string{"query", "osqueryd"},
	})
	if err != nil {
		logger.Warn("⚠️ Failed to query service status",
			zap.Error(err))
	} else {
		logger.Info("📊 Service status",
			zap.String("output", output))
	}

	return nil
}