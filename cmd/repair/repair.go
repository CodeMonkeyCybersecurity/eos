// cmd/repair/repair.go

package repair

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// RepairCmd is the root command for repair operations
var RepairCmd = &cobra.Command{
	Use:   "repair",
	Short: "Repair and fix common issues with Eos components",
	Long: `Automatically detect and fix common issues with Eos components.

The repair command can:
- Fix file permissions and ownership
- Repair configuration files
- Clean up duplicate binaries
- Restore missing files
- Fix systemd services
- Repair TLS certificates

EXAMPLES:
  # Auto-repair Vault installation
  sudo eos repair vault

  # Dry-run to see what would be fixed
  sudo eos repair vault --dry-run

  # Cleanup duplicate binaries
  sudo eos repair vault --cleanup-binaries`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}

// AddSubcommands adds all repair subcommands
func AddSubcommands() {
	RepairCmd.AddCommand(vaultRepairCmd)
	RepairCmd.AddCommand(metisRepairCmd)
}

func init() {
	AddSubcommands()
}
