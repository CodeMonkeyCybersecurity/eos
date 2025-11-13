// cmd/backup/restore-hecate.go

package backup

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var timestampFlag string

var RestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore configuration and files from backup",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
		// Delegate to pkg/backup for business logic
		if timestampFlag != "" {
			return backup.AutoRestore(rc, timestampFlag)
		}
		return backup.InteractiveRestore(rc, timestampFlag)
	}),
}

func init() {
	RestoreCmd.Flags().StringVarP(&timestampFlag, "timestamp", "t", "",
		"Backup timestamp (YYYYMMDD-HHMMSS). Omit for interactive mode.")
}

// All business logic has been migrated to pkg/backup/restore_hecate.go
// This file now contains only Cobra orchestration as per CLAUDE.md architecture rules
