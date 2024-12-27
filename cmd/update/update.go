/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
// cmd/update.go
package update

import (
	"github.com/spf13/cobra"
)

// UpdateCmd is the base command for update operations
var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update resources",
	Long:  `Use this command to update various resources such as processes, users, or storage.`,
}

// init initializes the update subcommands
func init() {
	// Register subcommands here
	UpdateCmd.AddCommand(updateProcessesCmd)
	UpdateCmd.AddCommand(updateUsersCmd)
	UpdateCmd.AddCommand(updateStorageCmd)
}
