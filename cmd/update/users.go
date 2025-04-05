// cmd/update/users.go
package update

import (
	"fmt"

	"github.com/spf13/cobra"
)

// updateUsersCmd handles updating user information
var UpdateUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Update users",
	Long:  `Use this command to update user information.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Please specify the user to update.")
			return
		}
		user := args[0]
		fmt.Printf("Updating user: %s\n", user)
		// Add your logic here
	},
}

func init() {
	UpdateCmd.AddCommand(UpdateUsersCmd)
}
