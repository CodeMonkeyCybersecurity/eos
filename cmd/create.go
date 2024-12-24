// create.go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// getCmd represents the "get" subcommand
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "create/alter information about resources (processes, users, backups, etc.)",
	Long:  `Use eos create to manage detailed information about system resources, such as processes, users, backups, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("You called `eos create` without specifying a resource.")
	},
}
