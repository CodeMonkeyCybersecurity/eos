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

var updateProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Update a process",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Updating a process...")
		// Add your logic here
	},
}

var updateUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Update a user",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Updating a user...")
		// Add your logic here
	},
}

var updateStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Update storage",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Updating storage...")
		// Add your logic here
	},
}
