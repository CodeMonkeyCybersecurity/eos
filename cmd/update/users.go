// cmd/update/users.go
package update

import (

	// "time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"

	// "github.com/CodeMonkeyCybersecurity/eos/pkg/hera"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/users"
	"github.com/spf13/cobra"
)

// updateUsersCmd handles updating user information
var UpdateUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Update user information and settings",
	Long: `Update user information and settings including passwords and SSH access.

Examples:
  eos update users password [username]  # Change user password
  eos update users ssh-access [username]  # Grant SSH access to user`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		shared.SafeHelp(cmd)
		return nil
	}),
}

var updateUserPasswordCmd = &cobra.Command{
	Use:   "password [username]",
	Short: "Change user password (replaces changeUserPassword.sh)",
	Long: `Change the password for an existing user account.
This replaces the changeUserPassword.sh script functionality.

Examples:
  eos update users password john     # Change password for user 'john'
  eos update users password          # Interactive mode - prompt for username`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return users.RunUpdateUserPassword(rc, cmd, args)
	}),
}

var updateUserSSHAccessCmd = &cobra.Command{
	Use:   "ssh-access [username]",
	Short: "Grant SSH access to a user",
	Long: `Grant SSH access to a user by adding them to the SSH AllowUsers configuration.
This functionality is part of the usersWithRemoteSsh.sh script migration.

Examples:
  eos update users ssh-access alice  # Grant SSH access to user 'alice'
  eos update users ssh-access        # Interactive mode - prompt for username`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return users.RunUpdateUserSSHAccess(rc, cmd, args)
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateUsersCmd)
	UpdateUsersCmd.AddCommand(updateUserPasswordCmd)
	UpdateUsersCmd.AddCommand(updateUserSSHAccessCmd)
}
