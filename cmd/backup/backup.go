// cmd/backup/backup.go

package backup

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// BackupCmd is the main backup command that follows CRUD pattern
var BackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Comprehensive backup and restore management using restic",
	Long: `Eos backup provides a unified interface for backup operations using restic.

Features:
  - Multiple repository support (local, SFTP, S3, B2, Azure, GCS)
  - Vault integration for secure password management
  - Backup profiles for common scenarios
  - Automated scheduling with systemd timers
  - Retention policies and pruning
  - Backup verification and testing
  - Progress monitoring and notifications

Examples:
  # Initialize a new repository
  eos backup create repository local --path /var/lib/eos/backups
  
  # Create a backup profile
  eos backup create profile system --repo local --paths /etc,/var,/opt
  
  # Run a backup
  eos backup update run system
  
  # List snapshots
  eos backup list snapshots --repo local
  
  # Restore from snapshot
  eos backup restore <snapshot-id> --target /tmp/restore`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("No subcommand provided for backup command")
		_ = cmd.Help()
		return nil
	}),
}

func init() {
	// Register CRUD subcommands
	BackupCmd.AddCommand(createCmd)
	BackupCmd.AddCommand(readCmd)
	BackupCmd.AddCommand(updateCmd)
	BackupCmd.AddCommand(deleteCmd)
	BackupCmd.AddCommand(listCmd)

	// Register additional subcommands
	BackupCmd.AddCommand(restoreCmd)
	BackupCmd.AddCommand(verifyCmd)
	BackupCmd.AddCommand(scheduleCmd)
	BackupCmd.AddCommand(fileCmd)
}
