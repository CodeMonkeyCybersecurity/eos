// cmd/delete/users.go
package delete

import (
	"fmt"

	"github.com/spf13/cobra"
)

// deleteUsersCmd represents the command to delete users
var deleteUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Delete users",
	Long:  `Delete users by specifying the target user.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Please specify the user to delete.")
			return
		}
		user := args[0]
		fmt.Printf("Deleting user: %s...\n", user)
		// Add your delete logic here
	},
}
