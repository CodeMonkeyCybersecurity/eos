// cmd/restore/restore.go
// Top-level restore command

package restore

import (
	"github.com/CodeMonkeyCybersecurity/eos/cmd/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// RestoreCmd is the top-level restore command
var RestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore from backups",
	Long: `Restore files and directories from backups.

Quick restore from "eos backup .":
  eos restore .                              # Restore latest to current directory
  eos restore . abc123                       # Restore specific snapshot
  eos restore . --list                       # List available snapshots

Restore from restic snapshots:
  eos backup restore <snapshot-id> --target /tmp/restore

Examples:
  cd /tmp && eos restore .                   # Restore to current directory
  eos restore . --target /etc                # Restore to /etc
  eos restore . --list                       # Show available snapshots`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for restore command")
		_ = cmd.Help()
		return nil
	}),
}

func init() {
	// Register quick restore subcommand
	RestoreCmd.AddCommand(backup.QuickRestoreCmd())
}
