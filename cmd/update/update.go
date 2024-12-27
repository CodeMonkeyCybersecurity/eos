package update

import (
	"fmt"

	"github.com/spf13/cobra"
)

// UpdateCmd is the root command for update operations
var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update resources (e.g., processes, users, storage)",
	Long:  `The update command allows you to modify existing resources such as processes, users, or storage.`,
}

// init registers subcommands for the update command
func init() {
	UpdateCmd.AddCommand(updateProcessesCmd)
	UpdateCmd.AddCommand(updateUsersCmd)
	UpdateCmd.AddCommand(updateStorageCmd)
}
