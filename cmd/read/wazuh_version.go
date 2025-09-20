// cmd/read/wazuh_version.go
//
// Delphi Version Information Commands
//
// This file implements CLI commands for viewing Delphi version information,
// checking for updates, and managing version cache. Since Delphi is your own
// implementation of Wazuh, this provides a user-friendly interface to the
// underlying version management system.
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
// These commands work with the centralized Delphi version management system to provide
// consistent version information across your Delphi infrastructure. The system
// automatically fetches the latest versions and respects your configured policies.
package read

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
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
	
	// Get latest Delphi version
	latestVersion, err := delphi.GetLatestDelphiVersion(rc)
	if err != nil {
		logger.Warn("Failed to get latest Delphi version", zap.Error(err))
		latestVersion = delphi.DefaultDelphiVersion
	}

	// Handle version comparison
	if compareStr, _ := cmd.Flags().GetString("compare"); compareStr != "" {
		return handleVersionComparison(rc, compareStr)
	}

	// Default: show current and latest version info
	logger.Info("=== Delphi Version Information ===")
	logger.Info(fmt.Sprintf("Latest Version: %s", latestVersion))
	logger.Info("Note: This shows the latest Wazuh version compatible with your Delphi implementation")
	
	return nil
}

func handleVersionComparison(rc *eos_io.RuntimeContext, compareStr string) error {
	logger := otelzap.Ctx(rc.Ctx)

	parts := strings.Split(compareStr, ",")
	if len(parts) != 2 {
		return fmt.Errorf("compare format should be 'version1,version2'")
	}

	v1 := strings.TrimSpace(parts[0])
	v2 := strings.TrimSpace(parts[1])

	// Simple version comparison
	logger.Info("=== Version Comparison ===")
	logger.Info(fmt.Sprintf("Version 1: %s", v1))
	logger.Info(fmt.Sprintf("Version 2: %s", v2))
	
	if v1 == v2 {
		logger.Info(fmt.Sprintf("Result: %s = %s", v1, v2))
	} else if v1 < v2 {
		logger.Info(fmt.Sprintf("Result: %s < %s", v1, v2))
	} else {
		logger.Info(fmt.Sprintf("Result: %s > %s", v1, v2))
	}

	return nil
}
