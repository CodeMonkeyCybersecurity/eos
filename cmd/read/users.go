// cmd/read/users.go
package read

import (
	"fmt"

	"github.com/spf13/cobra"
)

// readUsersCmd represents the command to read users
var readUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Read users",
	Long:  `Retrieve information about users.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading users...")
		// Add your read logic here
	},
}
