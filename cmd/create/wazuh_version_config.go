// cmd/create/wazuh_version_config.go
//
// # Wazuh Version Configuration Creation Commands
//
// This file implements CLI commands for creating initial Wazuh version management
// configurations. It provides templates for different environments and comprehensive
// configuration options for version management policies.
//
// Key Features:
// - Environment-specific templates (production, staging, development)
// - Interactive configuration setup (planned)
// - Flag-based custom configuration
// - Maintenance window scheduling
// - Update policy configuration
// - Safety controls and approval workflows
//
// Available Templates:
// - production: Conservative approach with manual updates and strict approval
//   - Update Policy: Manual (no automatic updates)
//   - Approval Required: Yes
//   - Backup Before Update: Yes
//   - Maintenance Window: Weekends, 2-4 AM UTC
//   - Best for: Production environments requiring maximum stability
//
// - staging: Moderate approach with patch auto-updates
//   - Update Policy: Patch (automatic patch updates only)
//   - Approval Required: Yes
//   - Backup Before Update: Yes
//   - Maintenance Window: Daily, 1-5 AM UTC
//   - Best for: Staging environments that need recent security patches
//
// - development: Aggressive approach with latest versions
//   - Update Policy: Latest (always use latest stable)
//   - Approval Required: No
//   - Backup Before Update: No
//   - Maintenance Window: Anytime
//   - Best for: Development environments needing cutting-edge features
//
// Usage Examples:
//
//	# Quick setup with templates
//	eos create wazuh-version-config --template production
//	eos create wazuh-version-config --template staging
//	eos create wazuh-version-config --template development
//
//	# Custom configuration
//	eos create wazuh-version-config --policy patch --auto-update --backup-before-update
//	eos create wazuh-version-config --pin-version 4.13.0 --require-approval
//
//	# Maintenance window configuration
//	eos create wazuh-version-config --template production --maintenance-start 2 --maintenance-end 4
//
// Integration:
// The created configuration integrates with the centralized version management
// system to control how Wazuh versions are selected and updated across your
// infrastructure. All Eos Wazuh deployment commands will respect these policies.
//
// Configuration Storage:
// Settings are stored in ~/.eos/wazuh-version-config.json and can be modified
// later using: eos update wazuh-version [options]
package create

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CreateWazuhVersionConfigCmd creates Wazuh version configuration
var CreateWazuhVersionConfigCmd = &cobra.Command{
	Use:   "wazuh-version-config",
	Short: "Create Wazuh version management configuration",
	Long: `Create and configure Wazuh version management policies.

This command helps you set up automated version management for Wazuh installations
with policies for updates, maintenance windows, and safety controls.

Configuration Templates:
  --template production    # Conservative: manual updates, approval required
  --template staging       # Moderate: patch updates, maintenance windows
  --template development   # Aggressive: latest versions, auto-updates

Examples:
  eos create wazuh-version-config --template production
  eos create wazuh-version-config --interactive
  eos create wazuh-version-config --policy patch --auto-update`,
	RunE: eos_cli.Wrap(runCreateWazuhVersionConfig),
}

func init() {
	CreateCmd.AddCommand(CreateWazuhVersionConfigCmd)

	// Template flags
	CreateWazuhVersionConfigCmd.Flags().String("template", "", "Use configuration template (production/staging/development)")
	CreateWazuhVersionConfigCmd.Flags().Bool("interactive", false, "Interactive configuration setup")

	// Policy flags
	CreateWazuhVersionConfigCmd.Flags().String("policy", "", "Update policy (manual/patch/minor/major/latest)")
	CreateWazuhVersionConfigCmd.Flags().Bool("auto-update", false, "Enable automatic updates")
	CreateWazuhVersionConfigCmd.Flags().Bool("require-approval", false, "Require manual approval")
	CreateWazuhVersionConfigCmd.Flags().Bool("backup-before-update", false, "Backup before updates")
	CreateWazuhVersionConfigCmd.Flags().Bool("test-environment", false, "Mark as test environment")

	// Version constraints
	CreateWazuhVersionConfigCmd.Flags().String("pin-version", "", "Pin to specific version")
	CreateWazuhVersionConfigCmd.Flags().String("min-version", "", "Minimum allowed version")
	CreateWazuhVersionConfigCmd.Flags().String("max-version", "", "Maximum allowed version")

	// Maintenance window
	CreateWazuhVersionConfigCmd.Flags().String("maintenance-start", "", "Maintenance window start hour (0-23)")
	CreateWazuhVersionConfigCmd.Flags().String("maintenance-end", "", "Maintenance window end hour (0-23)")
	CreateWazuhVersionConfigCmd.Flags().String("maintenance-days", "", "Maintenance days (0=Sun,1=Mon,...,6=Sat)")
	CreateWazuhVersionConfigCmd.Flags().String("timezone", "UTC", "Timezone for maintenance window")

	// Notification settings
	CreateWazuhVersionConfigCmd.Flags().Bool("notify-updates", false, "Enable update notifications")
	CreateWazuhVersionConfigCmd.Flags().String("notify-channels", "", "Notification channels (comma-separated)")

	// Other options
	CreateWazuhVersionConfigCmd.Flags().Bool("force", false, "Overwrite existing configuration")
}
// TODO: refactor - Move to pkg/wazuh/config_create.go
// GOOD PATTERN: This file actually follows best practices!
// POSITIVE OBSERVATIONS:
//   ✓ No package-level flag variables - uses cmd.Flags().Get*()
//   ✓ Uses logger.Info() with "terminal prompt:" prefix (follows CLAUDE.md)
//   ✓ Proper error handling with eos_err.NewUserError
//   ✓ Business logic delegated to pkg/wazuh.ConfigManager
// MINOR IMPROVEMENTS:
//   - Helper functions below could still move to pkg/wazuh/config_helpers.go
//   - This is more orchestration which is appropriate for cmd/
// MOVE: createFromTemplate, createFromFlags, configureMaintenanceWindow, showConfigurationSummary to pkg/
func runCreateWazuhVersionConfig(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	configManager := wazuh.NewConfigManager()

	// Check if configuration already exists
	if _, err := configManager.LoadConfig(rc); err == nil {
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			return eos_err.NewUserError("configuration already exists. Use --force to overwrite or 'eos update wazuh-version' to modify")
		}
		logger.Info("Overwriting existing configuration")
	}

	// Handle template-based configuration
	if template, _ := cmd.Flags().GetString("template"); template != "" {
		return createFromTemplate(rc, configManager, template)
	}

	// Handle interactive configuration
	if interactive, _ := cmd.Flags().GetBool("interactive"); interactive {
		return createInteractiveConfig(rc, configManager)
	}

	// Handle flag-based configuration
	return createFromFlags(rc, configManager, cmd)
}
// TODO: refactor - Move to pkg/wazuh/templates.go
// BUSINESS LOGIC: Template creation with hardcoded configurations
// This is pure business logic - creates config structs from template names
// MOVE TO: pkg/wazuh/templates.go as CreateConfigFromTemplate(template string) (*VersionConfig, error)
func createFromTemplate(rc *eos_io.RuntimeContext, configManager *wazuh.ConfigManager, template string) error {
	logger := otelzap.Ctx(rc.Ctx)

	var config *wazuh.VersionConfig

	switch template {
	case "production":
		config = &wazuh.VersionConfig{
			UpdatePolicy:       wazuh.UpdatePolicyManual,
			AutoUpdate:         false,
			RequireApproval:    true,
			TestEnvironment:    false,
			BackupBeforeUpdate: true,
			NotifyOnUpdate:     true,
			MaintenanceWindow: &wazuh.TimeWindow{
				StartHour: 2,           // 2 AM
				EndHour:   4,           // 4 AM
				Days:      []int{0, 6}, // Sunday and Saturday
				Timezone:  "UTC",
			},
		}
		logger.Info("Creating production configuration (conservative, manual updates)")

	case "staging":
		config = &wazuh.VersionConfig{
			UpdatePolicy:       wazuh.UpdatePolicyPatch,
			AutoUpdate:         true,
			RequireApproval:    true,
			TestEnvironment:    false,
			BackupBeforeUpdate: true,
			NotifyOnUpdate:     true,
			MaintenanceWindow: &wazuh.TimeWindow{
				StartHour: 1,                          // 1 AM
				EndHour:   5,                          // 5 AM
				Days:      []int{0, 1, 2, 3, 4, 5, 6}, // Every day
				Timezone:  "UTC",
			},
		}
		logger.Info("Creating staging configuration (moderate, patch auto-updates)")

	case "development":
		config = &wazuh.VersionConfig{
			UpdatePolicy:       wazuh.UpdatePolicyLatest,
			AutoUpdate:         true,
			RequireApproval:    false,
			TestEnvironment:    true,
			BackupBeforeUpdate: false,
			NotifyOnUpdate:     true,
			MaintenanceWindow: &wazuh.TimeWindow{
				StartHour: 0, // Any time
				EndHour:   23,
				Days:      []int{0, 1, 2, 3, 4, 5, 6}, // Every day
				Timezone:  "UTC",
			},
		}
		logger.Info("Creating development configuration (aggressive, latest auto-updates)")

	default:
		return eos_err.NewUserError("unknown template '%s'. Available: production, staging, development", template)
	}

	// Save configuration
	if err := configManager.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	logger.Info("Wazuh version configuration created successfully")
	return showConfigurationSummary(rc, config)
}
// TODO: refactor
func createInteractiveConfig(rc *eos_io.RuntimeContext, _ *wazuh.ConfigManager) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Interactive Wazuh version configuration setup")

	_ = wazuh.DefaultVersionConfig() // Reserved for future interactive implementation

	// This would be a full interactive setup in a real implementation
	// For now, we'll create a basic interactive flow
	logger.Info("terminal prompt: \n=== Wazuh Version Management Configuration ===")
	logger.Info("terminal prompt: \nFor a full interactive setup, please use the flag-based approach or templates.")
	logger.Info("terminal prompt: \nAvailable templates:")
	logger.Info("terminal prompt: - production: Conservative, manual updates")
	logger.Info("terminal prompt: - staging: Moderate, patch auto-updates")
	logger.Info("terminal prompt: - development: Aggressive, latest auto-updates")
	logger.Info("terminal prompt: \nExample: eos create wazuh-version-config --template production")

	return eos_err.NewUserError("interactive mode not fully implemented. Please use --template or flag-based configuration")
}
// TODO: refactor - Move to pkg/wazuh/config_parser.go
// BUSINESS LOGIC: Flag parsing and config creation
// ISSUE: Complex flag parsing logic belongs in pkg/
// MOVE TO: pkg/wazuh/config_parser.go as ParseConfigFromFlags(cmd *cobra.Command) (*VersionConfig, error)
// PATTERN: Similar to disk_manager.go - should create config struct in pkg/
func createFromFlags(rc *eos_io.RuntimeContext, configManager *wazuh.ConfigManager, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Start with default configuration
	config := wazuh.DefaultVersionConfig()

	// Apply flag-based overrides
	if policy, _ := cmd.Flags().GetString("policy"); policy != "" {
		switch policy {
		case "manual":
			config.UpdatePolicy = wazuh.UpdatePolicyManual
		case "patch":
			config.UpdatePolicy = wazuh.UpdatePolicyPatch
		case "minor":
			config.UpdatePolicy = wazuh.UpdatePolicyMinor
		case "major":
			config.UpdatePolicy = wazuh.UpdatePolicyMajor
		case "latest":
			config.UpdatePolicy = wazuh.UpdatePolicyLatest
		default:
			return eos_err.NewUserError("invalid policy '%s'. Valid: manual, patch, minor, major, latest", policy)
		}
	}

	if autoUpdate, _ := cmd.Flags().GetBool("auto-update"); autoUpdate {
		config.AutoUpdate = true
	}

	if requireApproval, _ := cmd.Flags().GetBool("require-approval"); requireApproval {
		config.RequireApproval = true
	}

	if backupBeforeUpdate, _ := cmd.Flags().GetBool("backup-before-update"); backupBeforeUpdate {
		config.BackupBeforeUpdate = true
	}

	if testEnvironment, _ := cmd.Flags().GetBool("test-environment"); testEnvironment {
		config.TestEnvironment = true
	}

	// Version constraints
	if pinVersion, _ := cmd.Flags().GetString("pin-version"); pinVersion != "" {
		config.PinnedVersion = pinVersion
	}

	if minVersion, _ := cmd.Flags().GetString("min-version"); minVersion != "" {
		config.MinimumVersion = minVersion
	}

	if maxVersion, _ := cmd.Flags().GetString("max-version"); maxVersion != "" {
		config.MaximumVersion = maxVersion
	}

	// Maintenance window
	if err := configureMaintenanceWindow(config, cmd); err != nil {
		return err
	}

	// Notifications
	if notifyUpdates, _ := cmd.Flags().GetBool("notify-updates"); notifyUpdates {
		config.NotifyOnUpdate = true
	}

	if channels, _ := cmd.Flags().GetString("notify-channels"); channels != "" {
		config.NotifyChannels = strings.Split(channels, ",")
		for i, channel := range config.NotifyChannels {
			config.NotifyChannels[i] = strings.TrimSpace(channel)
		}
	}

	// Save configuration
	if err := configManager.SaveConfig(rc, config); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	logger.Info("Wazuh version configuration created successfully")
	return showConfigurationSummary(rc, config)
}
// TODO: refactor - Move to pkg/wazuh/config_parser.go
// BUSINESS LOGIC: Parsing and validation of maintenance window settings
// MOVE TO: pkg/wazuh/config_parser.go as ParseMaintenanceWindow(cmd) (*TimeWindow, error)
func configureMaintenanceWindow(config *wazuh.VersionConfig, cmd *cobra.Command) error {
	startHour, _ := cmd.Flags().GetString("maintenance-start")
	endHour, _ := cmd.Flags().GetString("maintenance-end")
	days, _ := cmd.Flags().GetString("maintenance-days")
	timezone, _ := cmd.Flags().GetString("timezone")

	// Only create maintenance window if any maintenance flags are set
	if startHour != "" || endHour != "" || days != "" || cmd.Flags().Changed("timezone") {
		if config.MaintenanceWindow == nil {
			config.MaintenanceWindow = &wazuh.TimeWindow{
				StartHour: 2,
				EndHour:   4,
				Days:      []int{0, 6},
				Timezone:  "UTC",
			}
		}

		if startHour != "" {
			hour, err := strconv.Atoi(startHour)
			if err != nil || hour < 0 || hour > 23 {
				return eos_err.NewUserError("invalid start hour '%s'. Must be 0-23", startHour)
			}
			config.MaintenanceWindow.StartHour = hour
		}

		if endHour != "" {
			hour, err := strconv.Atoi(endHour)
			if err != nil || hour < 0 || hour > 23 {
				return eos_err.NewUserError("invalid end hour '%s'. Must be 0-23", endHour)
			}
			config.MaintenanceWindow.EndHour = hour
		}

		if days != "" {
			dayParts := strings.Split(days, ",")
			var dayInts []int
			for _, dayStr := range dayParts {
				dayStr = strings.TrimSpace(dayStr)
				day, err := strconv.Atoi(dayStr)
				if err != nil || day < 0 || day > 6 {
					return eos_err.NewUserError("invalid day '%s'. Must be 0-6 (0=Sunday)", dayStr)
				}
				dayInts = append(dayInts, day)
			}
			config.MaintenanceWindow.Days = dayInts
		}

		if timezone != "" {
			config.MaintenanceWindow.Timezone = timezone
		}
	}

	return nil
}
// TODO: refactor - Move to pkg/output/ or pkg/wazuh/display.go
// DISPLAY LOGIC: Formatting and displaying configuration summary
// GOOD: Uses logger.Info() with "terminal prompt:" (follows CLAUDE.md P0)
// MOVE TO: pkg/wazuh/display.go as DisplayConfigSummary(rc, config) error
// OR: pkg/output/wazuh.go if we want centralized output handling
func showConfigurationSummary(rc *eos_io.RuntimeContext, config *wazuh.VersionConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: \n=== Configuration Summary ===")
	logger.Info(fmt.Sprintf("terminal prompt: Update Policy: %s", config.UpdatePolicy))
	logger.Info(fmt.Sprintf("terminal prompt: Auto Update: %t", config.AutoUpdate))
	logger.Info(fmt.Sprintf("terminal prompt: Require Approval: %t", config.RequireApproval))
	logger.Info(fmt.Sprintf("terminal prompt: Backup Before Update: %t", config.BackupBeforeUpdate))
	logger.Info(fmt.Sprintf("terminal prompt: Test Environment: %t", config.TestEnvironment))

	if config.PinnedVersion != "" {
		logger.Info(fmt.Sprintf("terminal prompt: Pinned Version: %s", config.PinnedVersion))
	}

	if config.MaintenanceWindow != nil {
		logger.Info("terminal prompt: Maintenance Window:")
		logger.Info(fmt.Sprintf("terminal prompt:   Hours: %02d:00 - %02d:00",
			config.MaintenanceWindow.StartHour, config.MaintenanceWindow.EndHour))

		days := make([]string, len(config.MaintenanceWindow.Days))
		dayNames := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
		for i, day := range config.MaintenanceWindow.Days {
			days[i] = dayNames[day]
		}
		logger.Info(fmt.Sprintf("terminal prompt:   Days: %s", strings.Join(days, ", ")))
		logger.Info(fmt.Sprintf("terminal prompt:   Timezone: %s", config.MaintenanceWindow.Timezone))
	}

	logger.Info("terminal prompt: \nNext steps:")
	logger.Info("terminal prompt: 1. Check current version: eos read wazuh-version")
	logger.Info("terminal prompt: 2. Set current version: eos update wazuh-version --current <version>")
	logger.Info("terminal prompt: 3. Check for updates: eos read wazuh-version --check-update")

	// Save configuration location info
	homeDir, _ := os.UserHomeDir()
	configPath := fmt.Sprintf("%s/.eos/wazuh-version-config.json", homeDir)
	logger.Info(fmt.Sprintf("terminal prompt: \nConfiguration saved to: %s", configPath))

	return nil
}
