// go.go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// getCmd represents the "get" subcommand
var goCmd = &cobra.Command{
	Use:   "go",
	Short: "Execute commands about resources (processes, users, backups, etc.)",
	Long:  `Use eos go to execute commands and processes relating to system resources, such as system processes, users, backups, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("You called `eos go` without specifying a resource.")
	},
}
