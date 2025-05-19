// cmd/create/user.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
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
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		opts := system.CreateUserOptions{
			Username:   username,
			Auto:       auto,
			LoginShell: loginShell,
		}
		return system.RunCreateUser(opts)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateUserCmd)
	CreateUserCmd.Flags().StringVar(&username, "username", shared.EosID, "Username for the new account")
	CreateUserCmd.Flags().BoolVar(&auto, "auto", false, "Enable non-interactive auto mode with secure random password")
	CreateUserCmd.Flags().BoolVar(&loginShell, "login", false, "Allow login shell for this user (default is no shell)")
}
