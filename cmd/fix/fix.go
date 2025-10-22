// cmd/fix/fix.go

package fix

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// FixCmd is the root command for fix operations
var FixCmd = &cobra.Command{
	Use:   "fix",
	Short: "[DEPRECATED] Fix and repair common issues - use 'eos update <service> --fix'",
	Long: `⚠️  DEPRECATION WARNING:
The 'eos fix' command family is deprecated in favor of 'eos update <service> --fix'.

These commands will be removed in Eos v2.0.0 (approximately 6 months from now).

Migration guide:
  eos fix vault       →  eos update vault --fix
  eos fix consul      →  eos update consul --fix
  eos fix mattermost  →  eos update mattermost --fix

The new pattern provides configuration drift correction: comparing current
state against canonical state from 'eos create <service>' and automatically
correcting any drift (permissions, config values, missing files).

Legacy functionality (still works):
- Fix file permissions and ownership
- Repair configuration files
- Clean up duplicate binaries
- Restore missing files
- Fix systemd services
- Repair TLS certificates
- Fix container permissions

EXAMPLES (DEPRECATED - use 'eos update <service> --fix' instead):
  # Auto-fix Vault installation
  sudo eos fix vault

  # Dry-run to see what would be fixed
  sudo eos fix vault --dry-run

  # Fix Mattermost permissions
  sudo eos fix mattermost`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Warn("⚠️  DEPRECATION WARNING: The 'eos fix' command is deprecated")
		logger.Warn("   Use 'eos update <service> --fix' instead")
		logger.Warn("   These commands will be removed in Eos v2.0.0")
		logger.Info("")
		return cmd.Help()
	}),
}

// AddSubcommands adds all fix subcommands
func AddSubcommands() {
	FixCmd.AddCommand(vaultFixCmd)
	FixCmd.AddCommand(irisFixCmd)
	FixCmd.AddCommand(mattermostFixCmd)
	FixCmd.AddCommand(consulFixCmd)
}

func init() {
	AddSubcommands()
}
