// cmd/storage/storage.go
package storage

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// StorageCmd is the root command for storage management
var StorageCmd = &cobra.Command{
	Use:     "storage",
	Aliases: []string{"stor"},
	Short:   "Manage storage systems and filesystems",
	Long: `Storage commands allow you to manage various storage systems including ZFS, LVM, and filesystem operations.

Examples:
  eos storage zfs                     # Interactive ZFS management
  eos storage zfs list pools          # List ZFS pools
  eos storage zfs list filesystems    # List ZFS filesystems
  eos storage zfs expand <pool> <device>  # Expand ZFS pool
  eos storage zfs destroy pool <pool>     # Destroy ZFS pool
  eos storage zfs destroy filesystem <fs> # Destroy ZFS filesystem`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for storage", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Add subcommands to StorageCmd
	StorageCmd.AddCommand(NewZFSCmd())
}