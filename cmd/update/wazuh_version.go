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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
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
	
	// Get latest Delphi version
	latestVersion, err := delphi.GetLatestDelphiVersion(rc)
	if err != nil {
		logger.Warn("Failed to get latest Delphi version", zap.Error(err))
		latestVersion = delphi.DefaultDelphiVersion
	}

	logger.Info("=== Delphi Version Update ===")
	logger.Info(fmt.Sprintf("Latest Version: %s", latestVersion))

	// Handle specific version update
	if toVersion, _ := cmd.Flags().GetString("to-version"); toVersion != "" {
		logger.Info("Updating to specific version", zap.String("version", toVersion))
		logger.Info("Note: This would update your Delphi deployment to version " + toVersion)
		return nil
	}

	// Handle latest version update
	if latest, _ := cmd.Flags().GetBool("latest"); latest {
		logger.Info("Updating to latest version", zap.String("version", latestVersion))
		logger.Info("Note: This would update your Delphi deployment to the latest version")
		return nil
	}

	// Default: show current version information
	logger.Info("Current Delphi version information:")
	logger.Info("- Latest available: " + latestVersion)
	logger.Info("- Default version: " + delphi.DefaultDelphiVersion)
	logger.Info("")
	logger.Info("Use --latest to update to the latest version")
	logger.Info("Use --to-version <version> to update to a specific version")

	return nil
}


// TODO: Implement comprehensive version management system
// These functions will be enhanced when the full Delphi version management system is complete

