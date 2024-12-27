/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
//cmd/delete.go
package delete

import (
	"fmt"

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
	DeleteCmd.AddCommand(deleteProcessesCmd)
	DeleteCmd.AddCommand(deleteUsersCmd)
	DeleteCmd.AddCommand(deleteStorageCmd)
}

var deleteProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Delete a process",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Deleting a process...")
	},
}

var deleteUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Delete a user",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Deleting a user...")
	},
}

var deleteStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Delete storage",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Deleting storage...")
	},
}
