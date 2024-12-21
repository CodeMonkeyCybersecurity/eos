// delete.go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// getCmd represents the "get" subcommand
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete information about resources (processes, users, backups, etc.)",
	Long:  `Use eos delete to delete commands and processes relating to system resources, such as system processes, users, backups, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("You called `eos delete` without specifying a resource.")
	},
}
