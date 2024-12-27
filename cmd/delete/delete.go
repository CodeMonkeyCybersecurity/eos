/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
//cmd/delete.go
package delete

import (
	"github.com/spf13/cobra"
)

// DeleteCmd represents the base delete command
var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete resources",
	Long:  `Delete resources such as processes, users, storage, etc.`,
}

// Initialize subcommands for delete
func init() {
	DeleteCmd.AddCommand(deleteProcessesCmd)
	DeleteCmd.AddCommand(deleteUsersCmd)
	DeleteCmd.AddCommand(deleteStorageCmd)
}
