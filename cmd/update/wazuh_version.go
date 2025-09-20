// cmd/update/wazuh_version.go
//
// Wazuh Version Update Commands
//
// This file implements CLI commands for updating Wazuh version configuration and
// performing version updates. It provides comprehensive control over version
// management policies, constraints, and update behavior.
//
// Key Features:
// - Set current installed version tracking
// - Configure update policies (manual, patch, minor, major, latest)
// - Pin versions to prevent unwanted updates
// - Set version constraints (min/max versions)
// - Configure maintenance windows and approval workflows
// - Perform actual version updates with policy enforcement
// - Dry-run capabilities for testing changes
//
// Available Commands:
// - eos update wazuh-version --current 4.13.0           # Track current version
// - eos update wazuh-version --pin 4.13.0               # Pin to specific version
// - eos update wazuh-version --policy patch             # Set update policy
// - eos update wazuh-version --auto-update               # Enable auto updates
// - eos update wazuh-version --latest                    # Update to latest version
// - eos update wazuh-version --latest --force           # Force update ignoring policy
// - eos update wazuh-version --to-version 4.13.1        # Update to specific version
// - eos update wazuh-version --dry-run --latest         # Test what would happen
//
// Policy Examples:
// - manual: No automatic updates, all changes require explicit approval
// - patch: Allow patch updates (4.13.0 → 4.13.1) but block minor/major
// - minor: Allow minor updates (4.13.0 → 4.14.0) but block major
// - major: Allow all updates including major versions
// - latest: Always use the latest stable version
//
// Integration:
// This system integrates with the centralized version management to ensure
// consistent version policies across your Wazuh infrastructure. All updates
// respect your configured policies unless explicitly overridden with --force.
//
// Configuration:
// Settings are stored in ~/.eos/wazuh-version-config.json and can be created
// with templates using: eos create wazuh-version-config --template production
package update

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp/version"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateWazuhVersionCmd updates Wazuh version configuration
var UpdateWazuhVersionCmd = &cobra.Command{
	Use:   "wazuh-version",
	Short: "Update Wazuh version configuration",
	Long: `Update Wazuh version configuration and optionally update installations.

This command can:
- Set the current installed version
- Update version management policies
- Pin versions to prevent updates
- Configure automatic update settings

Examples:
  eos update wazuh-version --current 4.13.0           # Set current version
  eos update wazuh-version --pin 4.13.0               # Pin to specific version
  eos update wazuh-version --policy patch             # Set update policy
  eos update wazuh-version --auto-update               # Enable auto updates
  eos update wazuh-version --latest                    # Update to latest version
  eos update wazuh-version --latest --force           # Force update ignoring policy`,
	RunE: eos_cli.Wrap(runUpdateWazuhVersion),
}

func init() {
	UpdateCmd.AddCommand(UpdateWazuhVersionCmd)

	// Version management flags
	UpdateWazuhVersionCmd.Flags().String("current", "", "Set current installed version")
	UpdateWazuhVersionCmd.Flags().String("pin", "", "Pin to specific version (empty to unpin)")
	UpdateWazuhVersionCmd.Flags().String("policy", "", "Set update policy (manual/patch/minor/major/latest)")
	UpdateWazuhVersionCmd.Flags().String("min-version", "", "Set minimum allowed version")
	UpdateWazuhVersionCmd.Flags().String("max-version", "", "Set maximum allowed version")
	
	// Update behavior flags
	UpdateWazuhVersionCmd.Flags().Bool("auto-update", false, "Enable automatic updates")
	UpdateWazuhVersionCmd.Flags().Bool("disable-auto-update", false, "Disable automatic updates")
	UpdateWazuhVersionCmd.Flags().Bool("require-approval", false, "Require manual approval for updates")
	UpdateWazuhVersionCmd.Flags().Bool("no-approval", false, "Don't require manual approval")
	UpdateWazuhVersionCmd.Flags().Bool("backup", false, "Enable backup before updates")
	UpdateWazuhVersionCmd.Flags().Bool("no-backup", false, "Disable backup before updates")
	
	// Maintenance window flags
	UpdateWazuhVersionCmd.Flags().String("maintenance-hours", "", "Set maintenance window hours (e.g., '2-4')")
	UpdateWazuhVersionCmd.Flags().String("maintenance-days", "", "Set maintenance window days (e.g., '0,6' for Sun,Sat)")
	UpdateWazuhVersionCmd.Flags().String("timezone", "", "Set timezone for maintenance window")
	
	// Action flags
	UpdateWazuhVersionCmd.Flags().Bool("latest", false, "Update to latest version")
	UpdateWazuhVersionCmd.Flags().String("to-version", "", "Update to specific version")
	UpdateWazuhVersionCmd.Flags().Bool("force", false, "Force update ignoring policy restrictions")
	UpdateWazuhVersionCmd.Flags().Bool("dry-run", false, "Show what would be updated without making changes")
}

func runUpdateWazuhVersion(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	versionManager := version.NewManager()
	configManager := version.NewConfigManager()

	// Load current configuration
	config, err := configManager.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Track if any changes were made
	configChanged := false

	// Handle version setting
	if currentVersion, _ := cmd.Flags().GetString("current"); currentVersion != "" {
		logger.Info("Setting current version", zap.String("version", currentVersion))
		config.CurrentVersion = currentVersion
		configChanged = true
	}

	// Handle version pinning
	if pinVersion, _ := cmd.Flags().GetString("pin"); cmd.Flags().Changed("pin") {
		if pinVersion == "" {
			logger.Info("Unpinning version")
			config.PinnedVersion = ""
		} else {
			logger.Info("Pinning version", zap.String("version", pinVersion))
			config.PinnedVersion = pinVersion
		}
		configChanged = true
	}

	// Handle policy changes
	if policy, _ := cmd.Flags().GetString("policy"); policy != "" {
		if err := validateUpdatePolicy(policy); err != nil {
			return err
		}
		logger.Info("Setting update policy", zap.String("policy", policy))
		config.UpdatePolicy = version.UpdatePolicy(policy)
		configChanged = true
	}

	// Handle version constraints
	if minVersion, _ := cmd.Flags().GetString("min-version"); minVersion != "" {
		logger.Info("Setting minimum version", zap.String("version", minVersion))
		config.MinimumVersion = minVersion
		configChanged = true
	}

	if maxVersion, _ := cmd.Flags().GetString("max-version"); maxVersion != "" {
		logger.Info("Setting maximum version", zap.String("version", maxVersion))
		config.MaximumVersion = maxVersion
		configChanged = true
	}

	// Handle auto-update settings
	if autoUpdate, _ := cmd.Flags().GetBool("auto-update"); autoUpdate {
		logger.Info("Enabling automatic updates")
		config.AutoUpdate = true
		configChanged = true
	}

	if disableAutoUpdate, _ := cmd.Flags().GetBool("disable-auto-update"); disableAutoUpdate {
		logger.Info("Disabling automatic updates")
		config.AutoUpdate = false
		configChanged = true
	}

	// Handle approval settings
	if requireApproval, _ := cmd.Flags().GetBool("require-approval"); requireApproval {
		logger.Info("Enabling approval requirement")
		config.RequireApproval = true
		configChanged = true
	}

	if noApproval, _ := cmd.Flags().GetBool("no-approval"); noApproval {
		logger.Info("Disabling approval requirement")
		config.RequireApproval = false
		configChanged = true
	}

	// Handle backup settings
	if backup, _ := cmd.Flags().GetBool("backup"); backup {
		logger.Info("Enabling backup before updates")
		config.BackupBeforeUpdate = true
		configChanged = true
	}

	if noBackup, _ := cmd.Flags().GetBool("no-backup"); noBackup {
		logger.Info("Disabling backup before updates")
		config.BackupBeforeUpdate = false
		configChanged = true
	}

	// Handle maintenance window settings
	if hours, _ := cmd.Flags().GetString("maintenance-hours"); hours != "" {
		if err := updateMaintenanceHours(config, hours); err != nil {
			return err
		}
		configChanged = true
	}

	if days, _ := cmd.Flags().GetString("maintenance-days"); days != "" {
		if err := updateMaintenanceDays(config, days); err != nil {
			return err
		}
		configChanged = true
	}

	if timezone, _ := cmd.Flags().GetString("timezone"); timezone != "" {
		logger.Info("Setting maintenance window timezone", zap.String("timezone", timezone))
		if config.MaintenanceWindow == nil {
			config.MaintenanceWindow = &version.TimeWindow{}
		}
		config.MaintenanceWindow.Timezone = timezone
		configChanged = true
	}

	// Save configuration changes
	if configChanged {
		if err := configManager.SaveConfig(rc, config); err != nil {
			return fmt.Errorf("failed to save configuration: %w", err)
		}
		logger.Info("Configuration updated successfully")
	}

	// Handle version updates
	if updateToLatest, _ := cmd.Flags().GetBool("latest"); updateToLatest {
		return updateToLatestVersion(rc, versionManager, configManager, cmd)
	}

	if toVersion, _ := cmd.Flags().GetString("to-version"); toVersion != "" {
		return updateToSpecificVersion(rc, versionManager, configManager, toVersion, cmd)
	}

	// If no specific actions, show current configuration
	if !configChanged {
		return showCurrentConfiguration(rc, configManager)
	}

	return nil
}

func validateUpdatePolicy(policy string) error {
	validPolicies := []string{"manual", "patch", "minor", "major", "latest"}
	for _, valid := range validPolicies {
		if policy == valid {
			return nil
		}
	}
	return eos_err.NewUserError("invalid update policy '%s'. Valid options: %s", 
		policy, strings.Join(validPolicies, ", "))
}

func updateMaintenanceHours(config *version.VersionConfig, hours string) error {
	parts := strings.Split(hours, "-")
	if len(parts) != 2 {
		return eos_err.NewUserError("maintenance hours format should be 'start-end' (e.g., '2-4')")
	}

	var startHour, endHour int
	if _, err := fmt.Sscanf(parts[0], "%d", &startHour); err != nil {
		return eos_err.NewUserError("invalid start hour: %s", parts[0])
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &endHour); err != nil {
		return eos_err.NewUserError("invalid end hour: %s", parts[1])
	}

	if startHour < 0 || startHour > 23 || endHour < 0 || endHour > 23 {
		return eos_err.NewUserError("hours must be between 0 and 23")
	}

	if config.MaintenanceWindow == nil {
		config.MaintenanceWindow = &version.TimeWindow{}
	}
	config.MaintenanceWindow.StartHour = startHour
	config.MaintenanceWindow.EndHour = endHour

	return nil
}

func updateMaintenanceDays(config *version.VersionConfig, days string) error {
	dayParts := strings.Split(days, ",")
	var dayInts []int

	for _, dayStr := range dayParts {
		dayStr = strings.TrimSpace(dayStr)
		var day int
		if _, err := fmt.Sscanf(dayStr, "%d", &day); err != nil {
			return eos_err.NewUserError("invalid day: %s", dayStr)
		}
		if day < 0 || day > 6 {
			return eos_err.NewUserError("days must be between 0 (Sunday) and 6 (Saturday)")
		}
		dayInts = append(dayInts, day)
	}

	if config.MaintenanceWindow == nil {
		config.MaintenanceWindow = &version.TimeWindow{}
	}
	config.MaintenanceWindow.Days = dayInts

	return nil
}

func updateToLatestVersion(rc *eos_io.RuntimeContext, versionManager *version.Manager, configManager *version.ConfigManager, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	force, _ := cmd.Flags().GetBool("force")

	// Get latest version
	latestVersion, err := versionManager.GetLatestVersion(rc)
	if err != nil {
		return fmt.Errorf("failed to get latest version: %w", err)
	}

	// Load current config
	config, err := configManager.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	currentVer := config.CurrentVersion
	if currentVer == "" {
		currentVer = "4.13.0" // Default
	}

	logger.Info("Planning version update",
		zap.String("from", currentVer),
		zap.String("to", latestVersion.Version),
		zap.Bool("dry_run", dryRun),
		zap.Bool("force", force))

	// Check if update is needed
	if !versionManager.IsVersionNewer(latestVersion.Version, currentVer) {
		logger.Info("Already at latest version", zap.String("version", currentVer))
		return nil
	}

	// Check policy unless forced
	if !force {
		allowed, reason, err := configManager.ShouldUpdate(rc, currentVer, latestVersion.Version, versionManager)
		if err != nil {
			return fmt.Errorf("failed to check update policy: %w", err)
		}
		if !allowed {
			return eos_err.NewUserError("update blocked by policy: %s\nUse --force to override", reason)
		}
	}

	if dryRun {
		logger.Info("DRY RUN: Would update version",
			zap.String("from", currentVer),
			zap.String("to", latestVersion.Version))
		return nil
	}

	// Perform the update
	logger.Info("Updating to latest version", zap.String("version", latestVersion.Version))
	
	// Update configuration
	if err := configManager.UpdateCurrentVersion(rc, latestVersion.Version); err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}

	logger.Info("Version updated successfully",
		zap.String("from", currentVer),
		zap.String("to", latestVersion.Version))

	// Show next steps
	logger.Info("Next steps:")
	logger.Info("1. Update your Wazuh installations to use version " + latestVersion.Version)
	logger.Info("2. Update agent configurations to match the new version")
	logger.Info("3. Verify all components are running the new version")

	return nil
}

func updateToSpecificVersion(rc *eos_io.RuntimeContext, versionManager *version.Manager, configManager *version.ConfigManager, targetVersion string, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	force, _ := cmd.Flags().GetBool("force")

	// Validate target version exists
	versionInfo, err := versionManager.GetSpecificVersion(rc, targetVersion)
	if err != nil {
		return fmt.Errorf("version %s not found: %w", targetVersion, err)
	}

	// Load current config
	config, err := configManager.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	currentVer := config.CurrentVersion
	if currentVer == "" {
		currentVer = "4.13.0" // Default
	}

	logger.Info("Planning version update",
		zap.String("from", currentVer),
		zap.String("to", versionInfo.Version),
		zap.Bool("dry_run", dryRun),
		zap.Bool("force", force))

	// Check if update is needed
	if versionManager.CompareVersions(versionInfo.Version, currentVer) == 0 {
		logger.Info("Already at target version", zap.String("version", currentVer))
		return nil
	}

	// Check policy unless forced
	if !force {
		allowed, reason, err := configManager.ShouldUpdate(rc, currentVer, versionInfo.Version, versionManager)
		if err != nil {
			return fmt.Errorf("failed to check update policy: %w", err)
		}
		if !allowed {
			return eos_err.NewUserError("update blocked by policy: %s\nUse --force to override", reason)
		}
	}

	if dryRun {
		logger.Info("DRY RUN: Would update version",
			zap.String("from", currentVer),
			zap.String("to", versionInfo.Version))
		return nil
	}

	// Perform the update
	logger.Info("Updating to specific version", zap.String("version", versionInfo.Version))
	
	// Update configuration
	if err := configManager.UpdateCurrentVersion(rc, versionInfo.Version); err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}

	logger.Info("Version updated successfully",
		zap.String("from", currentVer),
		zap.String("to", versionInfo.Version))

	return nil
}

func showCurrentConfiguration(rc *eos_io.RuntimeContext, configManager *version.ConfigManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	config, err := configManager.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger.Info("=== Current Wazuh Version Configuration ===")
	logger.Info(fmt.Sprintf("Current Version: %s", config.CurrentVersion))
	logger.Info(fmt.Sprintf("Update Policy: %s", config.UpdatePolicy))
	logger.Info(fmt.Sprintf("Auto Update: %t", config.AutoUpdate))
	
	if config.PinnedVersion != "" {
		logger.Info(fmt.Sprintf("Pinned Version: %s", config.PinnedVersion))
	}

	logger.Info("\nUse 'eos read wazuh-version --config' for detailed configuration")

	return nil
}
