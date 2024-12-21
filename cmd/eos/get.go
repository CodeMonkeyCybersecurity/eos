// get.go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// getCmd represents the "get" subcommand
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Retrieve information about resources (processes, users, backups, etc.)",
	Long:  `Use eos get to retrieve detailed information about system resources, such as processes, users, backups, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("You called `eos get` without specifying a resource.")
	},
}
