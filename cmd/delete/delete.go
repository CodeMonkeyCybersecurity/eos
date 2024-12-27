/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
//cmd/delete.go
package delete

import (
	"github.com/spf13/cobra"
)

// DeleteCmd is the root command for delete operations
var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete resources (e.g., processes, users, storage)",
	Long:  `The delete command allows you to remove various resources such as processes, users, or storage.`,
}

// init registers subcommands for the delete command
func init() {
	DeleteCmd.AddCommand(deleteProcessCmd)
	DeleteCmd.AddCommand(deleteUsersCmd)
	DeleteCmd.AddCommand(deleteStorageCmd)
}
