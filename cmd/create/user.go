// cmd/create/user.go

package create

import (
	"fmt"

	"github.com/spf13/cobra"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/users"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var (
	username   string
	auto       bool
	loginShell bool
)

// Legacy command for backward compatibility
var CreateUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Create a new Linux user (legacy - use 'eos create user-account' for -based management)",
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

// Simple user creation command (replaces addUser.sh)
var createUserSimpleCmd = &cobra.Command{
	Use:   "user-simple",
	Short: "Create a new user account with interactive prompts (replaces addUser.sh)",
	Long: `Create a new user account using interactive prompts for username, password, and privileges.

This is a simple replacement for the addUser.sh script with the same functionality:
- Interactive username and password prompts
- Password confirmation for security
- Optional sudo privileges
- Optional SSH access
- Home directory creation with bash shell

FEATURES:
• Interactive username and password prompts
• Secure password confirmation
• Optional sudo privileges
• Optional SSH access configuration
• Automatic home directory creation
• Bash shell as default

EXAMPLES:
  # Interactive mode with prompts
  eos create user-simple

  # Create user with flags
  eos create user-simple --username john --sudo --ssh

  # Create user with specific password
  eos create user-simple --username alice --password mypass123`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("Starting simple user creation")

		// Check for command line arguments
		usernameFlag, _ := cmd.Flags().GetString("username")
		passwordFlag, _ := cmd.Flags().GetString("password")
		sudoFlag, _ := cmd.Flags().GetBool("sudo")
		sshFlag, _ := cmd.Flags().GetBool("ssh")

		// Use interactive mode if username not provided
		if usernameFlag == "" {
			return users.CreateUserInteractive(rc)
		}

		// Create user with provided options
		options := &users.UserCreationOptions{
			Username:   usernameFlag,
			Password:   passwordFlag,
			SudoAccess: sudoFlag,
			Shell:      "/bin/bash",
			SSHAccess:  sshFlag,
		}

		// Get password if not provided
		if options.Password == "" {
			var err error
			options.Password, err = eos_io.PromptSecurePassword(rc, "Enter password: ")
			if err != nil {
				return fmt.Errorf("failed to get password: %w", err)
			}
		}

		return users.CreateUser(rc, options)
	}),
}

// contains moved to pkg/shared/slice
// DEPRECATED: Use slice.Contains instead
/*
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
*/

// promptSecurePassword moved to pkg/eos_io
// DEPRECATED: Use eos_io.PromptSecurePassword instead
/*
func promptSecurePassword(rc *eos_io.RuntimeContext, prompt string) (string, error) {
	// Use the interaction package to prompt for password
	return interaction.PromptUser(rc, prompt)
}
*/

func init() {
	// Legacy command
	CreateCmd.AddCommand(CreateUserCmd)
	CreateUserCmd.Flags().StringVar(&username, "username", shared.EosID, "Username for the new account")
	CreateUserCmd.Flags().BoolVar(&auto, "auto", false, "Enable non-interactive auto mode with secure random password")
	CreateUserCmd.Flags().BoolVar(&loginShell, "login", false, "Allow login shell for this user (default is no shell)")

	// Simple user creation command (replaces addUser.sh)
	createUserSimpleCmd.Flags().String("username", "", "Username for the new account")
	createUserSimpleCmd.Flags().String("password", "", "Password for the new account")
	createUserSimpleCmd.Flags().Bool("sudo", false, "Grant sudo privileges to the user")
	createUserSimpleCmd.Flags().Bool("ssh", false, "Grant SSH access to the user")

	CreateCmd.AddCommand(CreateUserCmd)
	CreateCmd.AddCommand(createUserSimpleCmd)
}
