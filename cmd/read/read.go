// cmd/read.go
/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
package read

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ReadCmd is the root command for read operations
var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read resources (e.g., processes, users, storage)",
	Long:  `The read command retrieves information about various resources such as processes, users, or storage.`,
}

// init registers subcommands for the read command
func init() {
	ReadCmd.AddCommand(readProcessesCmd)
	ReadCmd.AddCommand(readUsersCmd)
	ReadCmd.AddCommand(readStorageCmd)
}

var readProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Read a process",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading a process...")
		// Add your logic here
	},
}

var readUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Read a user",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading a user...")
		// Add your logic here
	},
}

var readStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Read storage",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading storage...")
		// Add your logic here
	},
}
