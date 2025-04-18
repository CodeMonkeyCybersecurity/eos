// cmd/hecate/backup/backup.go

/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

*/

package backup

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

// backupCmd represents the backup command.
var BackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup configuration and files",
	Long:  `Backup important configuration directories and files.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

// log is a package-level variable for the Zap logger.
var log *zap.Logger

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()
}
