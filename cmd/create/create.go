// cmd/create/create.go
package create

import (
	"fmt"

	"github.com/spf13/cobra"
)

// CreateCmd is the root command for create operations
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create resources (e.g., processes, users, storage)",
	Long:  `The create command allows you to create various resources such as processes, users, or storage.`,
}

// init registers subcommands for the create command
func init() {
	CreateCmd.AddCommand(createProcessesCmd)
	CreateCmd.AddCommand(createUsersCmd)
	CreateCmd.AddCommand(createStorageCmd)
}

var createProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Create a new process",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Creating a new process...")
	},
}

var createUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Create a new user",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Creating a new user...")
	},
}

var createStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Create new storage",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Creating new storage...")
	},
}
