// cmd/update/users.go
package update

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/users"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
		return runUpdateUserPassword(rc, cmd, args)
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
		return runUpdateUserSSHAccess(rc, cmd, args)
	}),
}

func runUpdateUserPassword(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting user password update")

	// Use interactive mode if no username provided
	if len(args) == 0 {
		return users.ChangeUserPasswordInteractive(rc)
	}

	username := strings.TrimSpace(args[0])
	if username == "" {
		return users.ChangeUserPasswordInteractive(rc)
	}

	// Get new password interactively for security
	newPassword, err := interaction.PromptUser(rc, "Enter new password: ")
	if err != nil {
		return fmt.Errorf("failed to get new password: %w", err)
	}

	return users.ChangeUserPassword(rc, username, newPassword)
}

func runUpdateUserSSHAccess(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting SSH access grant")

	var username string
	if len(args) > 0 {
		username = strings.TrimSpace(args[0])
	}

	// If no username provided, prompt for it
	if username == "" {
		var err error
		username, err = interaction.PromptUser(rc, "Enter username to grant SSH access: ")
		if err != nil {
			return fmt.Errorf("failed to get username: %w", err)
		}
		username = strings.TrimSpace(username)
	}

	if username == "" {
		otelzap.Ctx(rc.Ctx).Error("No username provided")
		return fmt.Errorf("username cannot be empty")
	}

	return users.GrantSSHAccess(rc, username)
}

func init() {
	UpdateCmd.AddCommand(UpdateUsersCmd)
	UpdateUsersCmd.AddCommand(updateUserPasswordCmd)
	UpdateUsersCmd.AddCommand(updateUserSSHAccessCmd)
}
