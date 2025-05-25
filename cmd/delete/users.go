// cmd/delete/users.go
package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// deleteUsersCmd represents the command to delete users
var DeleteUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Delete users",
	Long:  `Delete users by specifying the target user.`,
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			zap.L().Fatal("Please specify the user to delete.")
		}
		user := args[0]
		zap.L().Info("Deleting user", zap.String("user", user))
		// Add your delete logic here.
		return nil
	}),
}

func init() {

	DeleteCmd.AddCommand(DeleteUsersCmd)

}
