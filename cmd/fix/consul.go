// cmd/fix/consul.go

package fix

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/fix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var consulFixCmd = &cobra.Command{
	Use:   "consul",
	Short: "Fix common Consul service issues",
	Long: `Automatically detect and fix common Consul service issues.

The fix command can:
- Fix file permissions on configuration and data directories
- Fix ownership of Consul files (consul user/group)
- Repair systemd service configuration
- Clean up duplicate processes
- Fix common configuration issues

This command combines the functionality of 'eos debug consul --fix'
with additional permission and ownership repairs.

EXAMPLES:
  # Auto-fix all Consul issues
  sudo eos fix consul

  # Dry-run to see what would be fixed
  sudo eos fix consul --dry-run

  # Fix permissions only
  sudo eos fix consul --permissions-only`,

	RunE: eos_cli.Wrap(runConsulFix),
}

func init() {
	consulFixCmd.Flags().Bool("dry-run", false, "Show what would be fixed without applying changes")
	consulFixCmd.Flags().Bool("permissions-only", false, "Only fix file permissions and ownership")
	consulFixCmd.Flags().Bool("skip-restart", false, "Don't restart Consul service after fixes")
}

func runConsulFix(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Parse flags
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	permissionsOnly, _ := cmd.Flags().GetBool("permissions-only")
	skipRestart, _ := cmd.Flags().GetBool("skip-restart")

	config := &fix.Config{
		DryRun:          dryRun,
		PermissionsOnly: permissionsOnly,
		SkipRestart:     skipRestart,
	}

	// Run fix operations
	return fix.RunFixes(rc, config)
}
