// cmd/update/users.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

// updateUsersCmd handles updating user information
var UpdateUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Update users",
	Long:  `Use this command to update user information.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			fmt.Println("Please specify the user to update.")
			return nil
		}
		user := args[0]
		fmt.Printf("Updating user: %s\n", user)
		// Add your logic here
		cmd.Help()
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateUsersCmd)
}
