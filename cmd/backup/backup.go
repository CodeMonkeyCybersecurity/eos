// cmd/backup/backup.go

package backup

import "github.com/spf13/cobra"

var BackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup utilities for EOS",
}

func init() {
	BackupCmd.AddCommand(BackupHecateCmd)
}
