// set.go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// getCmd represents the "get" subcommand
var setCmd = &cobra.Command{
	Use:   "set",
	Short: "Set/alter information about resources (processes, users, backups, etc.)",
	Long:  `Use eos set to manage detailed information about system resources, such as processes, users, backups, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("You called `eos set` without specifying a resource.")
	},
}
