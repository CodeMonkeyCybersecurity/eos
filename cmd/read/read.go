// cmd/read.go
/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
package read

import (
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
	ReadCmd.AddCommand(readProcessCmd)
	ReadCmd.AddCommand(readUsersCmd)
	ReadCmd.AddCommand(readStorageCmd)
}
