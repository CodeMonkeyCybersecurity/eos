// cmd/create/users.go

package create

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// createUsersCmd represents the create command for users
var createUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Create new users",
	Long:  `Create new user accounts in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please provide user details to create.")
		}
		userDetails := args[0]
		fmt.Printf("Creating user: %s...\n", userDetails)
		// Add your logic for user creation
	},
}

func init() {
	CreateCmd.AddCommand(createUsersCmd)
}
