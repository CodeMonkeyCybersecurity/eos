// cmd/fix/fix.go

package fix

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// FixCmd is the root command for fix operations
var FixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Fix and repair common issues with Eos components",
	Long: `Automatically detect and fix common issues with Eos components.

The fix command can:
- Fix file permissions and ownership
- Repair configuration files
- Clean up duplicate binaries
- Restore missing files
- Fix systemd services
- Repair TLS certificates
- Fix container permissions

EXAMPLES:
  # Auto-fix Vault installation
  sudo eos fix vault

  # Dry-run to see what would be fixed
  sudo eos fix vault --dry-run

  # Fix Mattermost permissions
  sudo eos fix mattermost`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}

// AddSubcommands adds all fix subcommands
func AddSubcommands() {
	FixCmd.AddCommand(vaultFixCmd)
	FixCmd.AddCommand(irisFixCmd)
	FixCmd.AddCommand(mattermostFixCmd)
}

func init() {
	AddSubcommands()
}
