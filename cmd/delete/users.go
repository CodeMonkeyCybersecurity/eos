// cmd/delete/users.go
package delete

import (
	"github.com/spf13/cobra"
eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"go.uber.org/zap"
)

// deleteUsersCmd represents the command to delete users
var DeleteUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Delete users",
	Long:  `Delete users by specifying the target user.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			log.Fatal("Please specify the user to delete.")
		}
		user := args[0]
		log.Info("Deleting user", zap.String("user", user))
		// Add your delete logic here.
		return nil 
	}),
}

func init() {

	DeleteCmd.AddCommand(DeleteUsersCmd)

}
