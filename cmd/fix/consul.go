// cmd/fix/consul.go

package fix

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/fix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var consulFixCmd = &cobra.Command{
	Use:   "consul",
	Short: "[DEPRECATED] Fix common Consul service issues - use 'eos update consul --fix'",
	Long: `  DEPRECATION WARNING:
This command is deprecated and will be removed in Eos v2.0.0 (approximately 6 months from now).

Use 'eos update consul --fix' instead for configuration drift correction.

Migration guide:
  eos fix consul            →  eos update consul --fix
  eos fix consul --dry-run  →  eos update consul --drift

The new 'eos update consul --fix' provides the same functionality with better
semantics: it compares current state against canonical state and corrects drift.

Legacy functionality (still works):
- Fix file permissions on configuration and data directories
- Fix ownership of Consul files (consul user/group)
- Repair systemd service configuration
- Clean up duplicate processes
- Fix common configuration issues

This command combines the functionality of 'eos debug consul --fix'
with additional permission and ownership repairs.

EXAMPLES (DEPRECATED - use 'eos update consul --fix' instead):
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
	logger := otelzap.Ctx(rc.Ctx)

	// Print deprecation warning
	logger.Warn("  DEPRECATION WARNING: 'eos fix consul' is deprecated")
	logger.Warn("   Use 'eos update consul --fix' instead")
	logger.Warn("   This command will be removed in Eos v2.0.0 (approximately 6 months from now)")
	logger.Info("")

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
