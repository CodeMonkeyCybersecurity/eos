// pkg/osquery/macos.go

package osquery

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installMacOS handles osquery installation on macOS using Homebrew only
func installMacOS(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("🍎 Installing osquery on macOS")

	// Check if running as root - Homebrew doesn't support root execution
	if os.Getuid() == 0 {
		logger.Error(" Cannot install osquery as root user",
			zap.String("reason", "Homebrew doesn't support root execution for security reasons"),
			zap.String("solution", "Run without sudo: 'eos create osquery'"),
			zap.String("note", "osquery installation will request sudo when needed for configuration"))
		return fmt.Errorf("homebrew doesn't support root execution - run as regular user")
	}

	// Check if Homebrew is available
	if !platform.IsCommandAvailable("brew") {
		logger.Error(" Homebrew not found",
			zap.String("requirement", "Homebrew is required for osquery installation on macOS"),
			zap.String("install_homebrew", "Visit https://brew.sh for installation instructions"),
			zap.String("troubleshooting", "Ensure Homebrew is installed and in your PATH"))
		return fmt.Errorf("homebrew not found - required for macOS osquery installation")
	}

	logger.Info("🍺 Using Homebrew to install osquery")
	return installMacOSBrew(rc)
}

// installMacOSBrew installs osquery using Homebrew
func installMacOSBrew(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if osquery is already installed via Homebrew (check both formula and cask)
	logger.Info("🔍 Checking if osquery is already installed")

	// First check if it's installed as a cask (most common for osquery)
	caskOutput, caskErr := execute.Run(rc.Ctx, execute.Options{
		Command: "brew",
		Args:    []string{"list", "--cask", "osquery"},
	})

	// Then check if it's installed as a formula (alternative)
	formulaOutput, formulaErr := execute.Run(rc.Ctx, execute.Options{
		Command: "brew",
		Args:    []string{"list", "--formula", "osquery"},
	})

	isAlreadyInstalled := (caskErr == nil && strings.Contains(caskOutput, "osquery")) ||
		(formulaErr == nil && strings.Contains(formulaOutput, "osquery"))

	if caskErr == nil && strings.Contains(caskOutput, "osquery") {
		logger.Info(" osquery is already installed via Homebrew (cask)")
	} else if formulaErr == nil && strings.Contains(formulaOutput, "osquery") {
		logger.Info(" osquery is already installed via Homebrew (formula)")
	}

	if isAlreadyInstalled {
		logger.Info(" osquery is already installed via Homebrew",
			zap.String("status", "skipping installation"))
	} else {
		// Update Homebrew
		logger.Info(" Updating Homebrew")
		if err := execute.RunSimple(rc.Ctx, "brew", "update"); err != nil {
			logger.Warn("Failed to update Homebrew",
				zap.Error(err),
				zap.String("note", "Continuing with installation"))
		}

		// Install osquery
		logger.Info(" Installing osquery via Homebrew")
		installOutput, installErr := execute.Run(rc.Ctx, execute.Options{
			Command: "brew",
			Args:    []string{"install", "osquery"},
		})

		if installErr != nil {
			// Check if it's already installed (Homebrew sometimes returns error for this)
			if strings.Contains(installOutput, "already installed") ||
				strings.Contains(installOutput, "latest version is already installed") {
				logger.Info(" osquery was already installed",
					zap.String("brew_output", strings.TrimSpace(installOutput)))
			} else {
				logger.Error(" Failed to install osquery via Homebrew",
					zap.Error(installErr),
					zap.String("brew_output", strings.TrimSpace(installOutput)),
					zap.String("troubleshooting", "Try 'brew doctor' to diagnose Homebrew issues"))
				return fmt.Errorf("brew install osquery: %w", installErr)
			}
		} else {
			logger.Info(" osquery installed successfully via Homebrew")
		}
	}

	// Configure osquery (this is needed whether it was just installed or already present)
	logger.Info(" Configuring osquery")
	if err := configureMacOSHomebrew(rc); err != nil {
		return err
	}

	logger.Info(" osquery setup completed successfully")
	return nil
}

// configureMacOSHomebrew configures osquery installed via Homebrew
func configureMacOSHomebrew(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create configuration directory
	configDir := "/var/osquery"
	logger.Info(" Creating configuration directory",
		zap.String("path", configDir))
	if err := execute.RunSimple(rc.Ctx, "sudo", "mkdir", "-p", configDir); err != nil {
		logger.Error(" Failed to create config directory",
			zap.Error(err),
			zap.String("path", configDir))
		return fmt.Errorf("create config directory: %w", err)
	}

	// Write configuration
	configPath := "/var/osquery/osquery.conf"
	logger.Info(" Writing osquery configuration",
		zap.String("path", configPath))
	configContent := defaultOsqueryConfig
	if err := os.WriteFile("/tmp/osquery.conf", []byte(configContent), 0644); err != nil {
		logger.Error(" Failed to write temporary config",
			zap.Error(err))
		return fmt.Errorf("write temporary config: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, "sudo", "cp", "/tmp/osquery.conf", configPath); err != nil {
		logger.Error(" Failed to copy configuration",
			zap.Error(err),
			zap.String("path", configPath))
		return fmt.Errorf("copy configuration: %w", err)
	}
	if err := os.Remove("/tmp/osquery.conf"); err != nil {
		logger.Warn("Failed to remove temporary config file",
			zap.String("path", "/tmp/osquery.conf"),
			zap.Error(err))
	}

	// Note about Homebrew's osquery service behavior
	logger.Info(" Homebrew osquery configuration notes",
		zap.String("note", "Homebrew's osquery doesn't automatically create a system LaunchDaemon"),
		zap.String("config_location", configPath),
		zap.String("manual_run", "Run 'osqueryi' for interactive queries"),
		zap.String("daemon_setup", "LaunchDaemon setup requires manual configuration if needed"))

	// Check if user wants to set up a custom LaunchDaemon
	logger.Info(" osquery is ready for interactive use",
		zap.String("interactive_command", "osqueryi"),
		zap.String("config_file", configPath),
		zap.String("note", "For daemon mode, manual LaunchDaemon configuration may be required"))

	return nil
}

// verifyMacOSInstallation verifies osquery installation on macOS (Homebrew)
func verifyMacOSInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Verifying osquery installation on macOS")

	// Check if osqueryi is available
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "osqueryi",
		Args:    []string{"--version"},
	})
	if err != nil {
		logger.Error(" osqueryi not found or not working",
			zap.Error(err),
			zap.String("troubleshooting", "Ensure osquery is properly installed via Homebrew"))
		return fmt.Errorf("osqueryi verification failed: %w", err)
	}

	// Clean up the version output and extract version number
	version := strings.TrimSpace(output)
	if version == "" {
		version = "unknown"
	} else {
		// Extract version from "osqueryi version X.X.X" format
		parts := strings.Fields(version)
		if len(parts) >= 3 && parts[1] == "version" {
			version = parts[2]
		}
	}

	logger.Info(" osquery verified successfully",
		zap.String("version", version))

	// Verify Homebrew installation (check both cask and formula)
	logger.Info("🔍 Verifying Homebrew installation")

	// Check cask installation first (most common)
	caskOutput, caskErr := execute.Run(rc.Ctx, execute.Options{
		Command: "brew",
		Args:    []string{"list", "--cask", "osquery"},
	})

	// Check formula installation as fallback
	formulaOutput, formulaErr := execute.Run(rc.Ctx, execute.Options{
		Command: "brew",
		Args:    []string{"list", "--formula", "osquery"},
	})

	if caskErr == nil && strings.Contains(caskOutput, "osquery") {
		logger.Info(" osquery is properly installed via Homebrew (cask)")
	} else if formulaErr == nil && strings.Contains(formulaOutput, "osquery") {
		logger.Info(" osquery is properly installed via Homebrew (formula)")
	} else {
		logger.Warn("osquery may not be installed via Homebrew",
			zap.String("note", "Binary is available but not detected in Homebrew cask or formula listings"),
			zap.String("troubleshooting", "This is normal if osquery was installed through other means"))
	}

	// Check configuration file
	configPath := "/var/osquery/osquery.conf"
	if _, err := os.Stat(configPath); err != nil {
		logger.Warn("osquery configuration file not found",
			zap.String("path", configPath),
			zap.String("note", "Configuration may need to be created"))
	} else {
		logger.Info(" osquery configuration file exists",
			zap.String("path", configPath))
	}

	// Note about daemon mode
	logger.Info(" osquery installation summary",
		zap.String("mode", "interactive"),
		zap.String("command", "osqueryi"),
		zap.String("config", configPath),
		zap.String("note", "Homebrew osquery is configured for interactive use. Daemon mode requires additional setup."))

	return nil
}
