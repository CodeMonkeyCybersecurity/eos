// cmd/delete/users.go
package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// deleteUsersCmd represents the command to delete users
var DeleteUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Delete users",
	Long:  `Delete users by specifying the target user.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			otelzap.Ctx(rc.Ctx).Fatal("Please specify the user to delete.")
		}
		user := args[0]
		otelzap.Ctx(rc.Ctx).Info("Deleting user", zap.String("user", user))
		// Add your delete logic here.
		return nil
	}),
}

func init() {

	DeleteCmd.AddCommand(DeleteUsersCmd)

}
