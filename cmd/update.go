// update.go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// getCmd represents the "get" subcommand
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Execute commands about resources (processes, users, backups, etc.)",
	Long:  `Use eos update to execute commands and processes relating to system resources, such as system processes, users, backups, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("You called `eos update` without specifying a resource.")
	},
}
