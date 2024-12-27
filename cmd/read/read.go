// cmd/read.go
/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/

package read

import (
	"github.com/spf13/cobra"
)

// ReadCmd represents the base read command
var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read resources",
	Long:  `Read information about resources such as processes, users, storage, etc.`,
}

// Initialize subcommands for read
func init() {
	ReadCmd.AddCommand(readProcessesCmd)
	ReadCmd.AddCommand(readUsersCmd)
}
