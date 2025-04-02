// cmd/delete/users.go
package delete

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// deleteUsersCmd represents the command to delete users
var DeleteUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Delete users",
	Long:  `Delete users by specifying the target user.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatal("Please specify the user to delete.")
		}
		user := args[0]
		log.Info("Deleting user", zap.String("user", user))
		// Add your delete logic here.
	},
}

func init() {

	DeleteCmd.AddCommand(DeleteUsersCmd)

}
