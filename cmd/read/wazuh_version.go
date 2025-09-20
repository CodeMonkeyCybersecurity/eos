// cmd/read/wazuh_version.go
//
// Wazuh Version Information Commands
//
// This file implements CLI commands for viewing Wazuh version information,
// checking for updates, and managing version cache. It provides a user-friendly
// interface to the underlying version management system.
//
// Available Commands:
// - eos read wazuh-version                    # Show current and latest versions
// - eos read wazuh-version --list             # List all available versions
// - eos read wazuh-version --check-update     # Check if updates are available
// - eos read wazuh-version --config           # Show version configuration
// - eos read wazuh-version --compare v1,v2    # Compare two versions
// - eos read wazuh-version --clear-cache      # Clear version cache
//
// Integration:
// These commands work with the centralized version management system to provide
// consistent version information across your Wazuh infrastructure. The system
// automatically fetches the latest versions and respects your configured policies.
package read

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp/version"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReadWazuhVersionCmd shows Wazuh version information
var ReadWazuhVersionCmd = &cobra.Command{
	Use:   "wazuh-version",
	Short: "Show Wazuh version information",
	Long: `Show Wazuh version information including:
- Current installed version
- Latest available version
- Version update policy
- Available versions

Examples:
  eos read wazuh-version                    # Show current and latest versions
  eos read wazuh-version --list             # List all available versions
  eos read wazuh-version --check-update     # Check if updates are available
  eos read wazuh-version --config           # Show version configuration`,
	RunE: eos_cli.Wrap(runReadWazuhVersion),
}

func init() {
	ReadCmd.AddCommand(ReadWazuhVersionCmd)

	// Flags
	ReadWazuhVersionCmd.Flags().Bool("list", false, "List all available versions")
	ReadWazuhVersionCmd.Flags().Bool("list-prerelease", false, "Include pre-release versions in list")
	ReadWazuhVersionCmd.Flags().Bool("check-update", false, "Check if updates are available")
	ReadWazuhVersionCmd.Flags().Bool("config", false, "Show version configuration")
	ReadWazuhVersionCmd.Flags().Bool("clear-cache", false, "Clear version cache")
	ReadWazuhVersionCmd.Flags().String("compare", "", "Compare two versions (format: 'version1,version2')")
}

func runReadWazuhVersion(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	versionManager := version.NewManager()
	configManager := version.NewConfigManager()

	// Handle clear cache
	if clearCache, _ := cmd.Flags().GetBool("clear-cache"); clearCache {
		if err := versionManager.ClearCache(); err != nil {
			return fmt.Errorf("failed to clear cache: %w", err)
		}
		logger.Info("Version cache cleared successfully")
		return nil
	}

	// Handle version comparison
	if compareStr, _ := cmd.Flags().GetString("compare"); compareStr != "" {
		return handleVersionComparison(rc, versionManager, compareStr)
	}

	// Handle configuration display
	if showConfig, _ := cmd.Flags().GetBool("config"); showConfig {
		return showVersionConfiguration(rc, configManager)
	}

	// Handle version listing
	if listVersions, _ := cmd.Flags().GetBool("list"); listVersions {
		includePrerelease, _ := cmd.Flags().GetBool("list-prerelease")
		return listAvailableVersions(rc, versionManager, includePrerelease)
	}

	// Handle update checking
	if checkUpdate, _ := cmd.Flags().GetBool("check-update"); checkUpdate {
		return checkForUpdates(rc, versionManager, configManager)
	}

	// Default: show current and latest version info
	return showVersionInfo(rc, versionManager, configManager)
}

func showVersionInfo(rc *eos_io.RuntimeContext, versionManager *version.Manager, configManager *version.ConfigManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Load configuration
	config, err := configManager.LoadConfig(rc)
	if err != nil {
		logger.Warn("Failed to load configuration", zap.Error(err))
		config = version.DefaultVersionConfig()
	}

	// Get latest version
	latestVersion, err := versionManager.GetLatestVersion(rc)
	if err != nil {
		logger.Warn("Failed to get latest version", zap.Error(err))
	}

	// Display information
	logger.Info("=== Wazuh Version Information ===")
	
	if config.CurrentVersion != "" {
		logger.Info(fmt.Sprintf("Current Version: %s", config.CurrentVersion))
		if !config.LastUpdated.IsZero() {
			logger.Info(fmt.Sprintf("Last Updated: %s", config.LastUpdated.Format(time.RFC3339)))
		}
	} else {
		logger.Info("Current Version: Not set (will use default)")
	}

	if latestVersion != nil {
		logger.Info(fmt.Sprintf("Latest Version: %s", latestVersion.Version))
		logger.Info(fmt.Sprintf("Release Date: %s", latestVersion.ReleaseDate.Format("2006-01-02")))
		logger.Info(fmt.Sprintf("Stable: %t", latestVersion.IsStable))
		
		// Check if update is available
		currentVer := config.CurrentVersion
		if currentVer == "" {
			currentVer = "4.13.0" // Default
		}
		
		if versionManager.IsVersionNewer(latestVersion.Version, currentVer) {
			logger.Info(fmt.Sprintf("🔄 Update Available: %s → %s", currentVer, latestVersion.Version))
			
			// Check if update is allowed
			allowed, reason, err := configManager.ShouldUpdate(rc, currentVer, latestVersion.Version, versionManager)
			if err != nil {
				logger.Warn("Failed to check update policy", zap.Error(err))
			} else if allowed {
				logger.Info("✅ Update allowed by current policy")
			} else {
				logger.Info(fmt.Sprintf("❌ Update blocked: %s", reason))
			}
		} else {
			logger.Info("✅ You have the latest version")
		}
	}

	logger.Info(fmt.Sprintf("Update Policy: %s", config.UpdatePolicy))
	logger.Info(fmt.Sprintf("Auto Update: %t", config.AutoUpdate))
	
	if config.PinnedVersion != "" {
		logger.Info(fmt.Sprintf("📌 Pinned Version: %s", config.PinnedVersion))
	}

	return nil
}

func listAvailableVersions(rc *eos_io.RuntimeContext, versionManager *version.Manager, includePrerelease bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	versions, err := versionManager.ListAvailableVersions(rc, includePrerelease)
	if err != nil {
		return fmt.Errorf("failed to list versions: %w", err)
	}

	logger.Info("=== Available Wazuh Versions ===")
	
	for i, v := range versions {
		status := "Stable"
		if !v.IsStable {
			status = "Pre-release"
		}
		
		logger.Info(fmt.Sprintf("%2d. %s (%s) - Released: %s", 
			i+1, v.Version, status, v.ReleaseDate.Format("2006-01-02")))
		
		if i >= 19 { // Limit to 20 versions
			logger.Info(fmt.Sprintf("... and %d more versions", len(versions)-20))
			break
		}
	}

	return nil
}

func checkForUpdates(rc *eos_io.RuntimeContext, versionManager *version.Manager, configManager *version.ConfigManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := configManager.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	latestVersion, err := versionManager.GetLatestVersion(rc)
	if err != nil {
		return fmt.Errorf("failed to get latest version: %w", err)
	}

	currentVer := config.CurrentVersion
	if currentVer == "" {
		currentVer = "4.13.0" // Default
	}

	logger.Info("=== Update Check ===")
	logger.Info(fmt.Sprintf("Current: %s", currentVer))
	logger.Info(fmt.Sprintf("Latest:  %s", latestVersion.Version))

	if versionManager.IsVersionNewer(latestVersion.Version, currentVer) {
		logger.Info("🔄 Update available!")
		
		allowed, reason, err := configManager.ShouldUpdate(rc, currentVer, latestVersion.Version, versionManager)
		if err != nil {
			return fmt.Errorf("failed to check update policy: %w", err)
		}

		if allowed {
			logger.Info("✅ Update allowed by current policy")
			logger.Info("Run 'eos update wazuh-version' to update")
		} else {
			logger.Info(fmt.Sprintf("❌ Update blocked: %s", reason))
			logger.Info("Use 'eos update wazuh-version --force' to override policy")
		}
	} else {
		logger.Info("✅ You have the latest version")
	}

	return nil
}

func showVersionConfiguration(rc *eos_io.RuntimeContext, configManager *version.ConfigManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := configManager.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger.Info("=== Wazuh Version Configuration ===")
	logger.Info(fmt.Sprintf("Update Policy: %s", config.UpdatePolicy))
	logger.Info(fmt.Sprintf("Auto Update: %t", config.AutoUpdate))
	logger.Info(fmt.Sprintf("Require Approval: %t", config.RequireApproval))
	logger.Info(fmt.Sprintf("Backup Before Update: %t", config.BackupBeforeUpdate))
	logger.Info(fmt.Sprintf("Test Environment: %t", config.TestEnvironment))
	
	if config.PinnedVersion != "" {
		logger.Info(fmt.Sprintf("Pinned Version: %s", config.PinnedVersion))
	}
	
	if config.MinimumVersion != "" {
		logger.Info(fmt.Sprintf("Minimum Version: %s", config.MinimumVersion))
	}
	
	if config.MaximumVersion != "" {
		logger.Info(fmt.Sprintf("Maximum Version: %s", config.MaximumVersion))
	}

	if config.MaintenanceWindow != nil {
		logger.Info("Maintenance Window:")
		logger.Info(fmt.Sprintf("  Hours: %02d:00 - %02d:00", 
			config.MaintenanceWindow.StartHour, config.MaintenanceWindow.EndHour))
		
		days := make([]string, len(config.MaintenanceWindow.Days))
		dayNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
		for i, day := range config.MaintenanceWindow.Days {
			days[i] = dayNames[day]
		}
		logger.Info(fmt.Sprintf("  Days: %s", strings.Join(days, ", ")))
		logger.Info(fmt.Sprintf("  Timezone: %s", config.MaintenanceWindow.Timezone))
	}

	logger.Info(fmt.Sprintf("Cache Timeout: %s", config.CacheTimeout))
	
	if !config.LastChecked.IsZero() {
		logger.Info(fmt.Sprintf("Last Checked: %s", config.LastChecked.Format(time.RFC3339)))
	}

	return nil
}

func handleVersionComparison(rc *eos_io.RuntimeContext, versionManager *version.Manager, compareStr string) error {
	logger := otelzap.Ctx(rc.Ctx)

	parts := strings.Split(compareStr, ",")
	if len(parts) != 2 {
		return fmt.Errorf("compare format should be 'version1,version2'")
	}

	v1 := strings.TrimSpace(parts[0])
	v2 := strings.TrimSpace(parts[1])

	result := versionManager.CompareVersions(v1, v2)
	
	logger.Info("=== Version Comparison ===")
	logger.Info(fmt.Sprintf("Version 1: %s", v1))
	logger.Info(fmt.Sprintf("Version 2: %s", v2))
	
	switch result {
	case -1:
		logger.Info(fmt.Sprintf("Result: %s < %s", v1, v2))
	case 0:
		logger.Info(fmt.Sprintf("Result: %s = %s", v1, v2))
	case 1:
		logger.Info(fmt.Sprintf("Result: %s > %s", v1, v2))
	}

	return nil
}
