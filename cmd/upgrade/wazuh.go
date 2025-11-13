// cmd/upgrade/wazuh.go
//
// # Wazuh Version Upgrade Commands
//
// This file implements CLI commands for upgrading Wazuh to newer versions.
// It provides comprehensive control over version management policies, constraints,
// and upgrade behavior.
//
// Key Features:
// - Set current installed version tracking
// - Configure update policies (manual, patch, minor, major, latest)
// - Pin versions to prevent unwanted updates
// - Set version constraints (min/max versions)
// - Configure maintenance windows and approval workflows
// - Perform actual version upgrades with policy enforcement
// - Dry-run capabilities for testing changes
//
// Available Commands:
// - eos upgrade wazuh --current 4.13.0           # Track current version
// - eos upgrade wazuh --pin 4.13.0               # Pin to specific version
// - eos upgrade wazuh --policy patch             # Set upgrade policy
// - eos upgrade wazuh --auto-upgrade             # Enable auto upgrades
// - eos upgrade wazuh --latest                   # Upgrade to latest version
// - eos upgrade wazuh --latest --force           # Force upgrade ignoring policy
// - eos upgrade wazuh --to-version 4.13.1        # Upgrade to specific version
// - eos upgrade wazuh --dry-run --latest         # Test what would happen
//
// Policy Examples:
// - manual: No automatic upgrades, all changes require explicit approval
// - patch: Allow patch upgrades (4.13.0 → 4.13.1) but block minor/major
// - minor: Allow minor upgrades (4.13.0 → 4.14.0) but block major
// - major: Allow all upgrades including major versions
// - latest: Always use the latest stable version
//
// Integration:
// This system integrates with the centralized version management to ensure
// consistent version policies across your Wazuh infrastructure. All upgrades
// respect your configured policies unless explicitly overridden with --force.
//
// Configuration:
// Settings are stored in ~/.eos/wazuh-version-config.json and can be created
// with templates using: eos create wazuh-version-config --template production
package upgrade

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/spf13/cobra"
)

// WazuhCmd upgrades Wazuh version
var WazuhCmd = &cobra.Command{
	Use:   "wazuh",
	Short: "Upgrade Wazuh to newer versions",
	Long: `Upgrade Wazuh version and manage upgrade policies.

This command can:
- Upgrade to the latest version
- Upgrade to a specific version
- Set version management policies
- Pin versions to prevent upgrades
- Configure automatic upgrade settings

Examples:
  eos upgrade wazuh --current 4.13.0           # Set current version
  eos upgrade wazuh --pin 4.13.0               # Pin to specific version
  eos upgrade wazuh --policy patch             # Set upgrade policy
  eos upgrade wazuh --auto-upgrade             # Enable auto upgrades
  eos upgrade wazuh --latest                   # Upgrade to latest version
  eos upgrade wazuh --latest --force           # Force upgrade ignoring policy`,
	RunE: eos_cli.Wrap(wazuh.RunUpgradeWazuh),
}

func init() {
	// Version management flags
	WazuhCmd.Flags().String("current", "", "Set current installed version")
	WazuhCmd.Flags().String("pin", "", "Pin to specific version (empty to unpin)")
	WazuhCmd.Flags().String("policy", "", "Set upgrade policy (manual/patch/minor/major/latest)")
	WazuhCmd.Flags().String("min-version", "", "Set minimum allowed version")
	WazuhCmd.Flags().String("max-version", "", "Set maximum allowed version")

	// Upgrade behavior flags
	WazuhCmd.Flags().Bool("auto-upgrade", false, "Enable automatic upgrades")
	WazuhCmd.Flags().Bool("disable-auto-upgrade", false, "Disable automatic upgrades")
	WazuhCmd.Flags().Bool("require-approval", false, "Require manual approval for upgrades")
	WazuhCmd.Flags().Bool("no-approval", false, "Don't require manual approval")
	WazuhCmd.Flags().Bool("backup", false, "Enable backup before upgrades")
	WazuhCmd.Flags().Bool("no-backup", false, "Disable backup before upgrades")

	// Maintenance window flags
	WazuhCmd.Flags().String("maintenance-hours", "", "Set maintenance window hours (e.g., '2-4')")
	WazuhCmd.Flags().String("maintenance-days", "", "Set maintenance window days (e.g., '0,6' for Sun,Sat)")
	WazuhCmd.Flags().String("timezone", "", "Set timezone for maintenance window")

	// Action flags
	WazuhCmd.Flags().Bool("latest", false, "Upgrade to latest version")
	WazuhCmd.Flags().String("to-version", "", "Upgrade to specific version")
	WazuhCmd.Flags().Bool("force", false, "Force upgrade ignoring policy restrictions")
	WazuhCmd.Flags().Bool("dry-run", false, "Show what would be upgraded without making changes")
}
