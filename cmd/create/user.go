// cmd/create/user.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
)

var (
	username   string
	auto       bool
	loginShell bool
)

var CreateUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Create a new Linux user",
	Long:  `Creates a new user account and optionally adds them to the admin group, generates SSH keys, and sets a secure password.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		opts := eos_unix.CreateUserOptions{
			Username:   username,
			Auto:       auto,
			LoginShell: loginShell,
		}
		return eos_unix.RunCreateUser(rc.Ctx, opts)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateUserCmd)
	CreateUserCmd.Flags().StringVar(&username, "username", shared.EosID, "Username for the new account")
	CreateUserCmd.Flags().BoolVar(&auto, "auto", false, "Enable non-interactive auto mode with secure random password")
	CreateUserCmd.Flags().BoolVar(&loginShell, "login", false, "Allow login shell for this user (default is no shell)")
}
