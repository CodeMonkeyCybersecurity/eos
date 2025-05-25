// cmd/hecate/backup/backup.go

/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/

package backup

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// backupCmd represents the backup command.
var BackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup configuration and files",
	Long:  `Backup important configuration directories and files.`,
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

// log is a package-level variable for the Zap logger.

func init() {
	// Initialize the shared logger for the entire deploy package

}
