// cmd/create/create.go
package create

import (
	"github.com/spf13/cobra"
)

// CreateCmd represents the base create command
var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create resources like users, processes, storage, etc.",
	Long:  `The create command allows you to create various resources.`,
}
