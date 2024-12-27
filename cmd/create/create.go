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