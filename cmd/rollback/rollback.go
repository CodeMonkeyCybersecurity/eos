package rollback

import (
	"github.com/spf13/cobra"
)

// RollbackCmd is the root command for rollback operations
var RollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback failed operations",
	Long: `Rollback failed operations using available recovery methods including:
- LVM snapshots (fastest and safest)
- Reverse operations (for simple operations)
- Manual instructions (when automatic rollback isn't possible)

The rollback system uses operation journals to track what was done
and provides multiple recovery strategies based on available data.`,
}

func init() {
	// Add subcommands
	RollbackCmd.AddCommand(DiskOperationCmd)
}