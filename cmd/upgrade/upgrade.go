// cmd/upgrade/upgrade.go
package upgrade

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpgradeCmd is the root command for upgrade operations
var UpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade services to newer versions",
	Long: `The upgrade command allows you to upgrade services to newer versions.

This is different from 'update' which modifies configurations.
Upgrade handles version changes with breaking change management.

Available upgrades:
  hecate --authentik  - Upgrade Authentik identity provider to newer version

Examples:
  eos upgrade hecate --authentik                    # Upgrade Authentik with prompts
  eos upgrade hecate --authentik --target-version 2025.8  # Upgrade to specific version`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for upgrade command", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Add subcommands here
	UpgradeCmd.AddCommand(HecateCmd)
	UpgradeCmd.AddCommand(KVMCmd)
	UpgradeCmd.AddCommand(WazuhCmd)
}
