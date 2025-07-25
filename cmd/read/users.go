// cmd/inspect/users.go
package read

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/users"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// readUsersCmd represents the command to read users
var InspectUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Retrieve information about system users",
	Long: `This command retrieves information about system users including:
- All system users from /etc/passwd
- Users with SSH access (replaces part of usersWithRemoteSsh.sh)
- User hostname stamps

The command provides three modes of operation:
1. Default: Lists all system users from /etc/passwd
2. SSH-only: Lists only users with SSH access capabilities
3. Stamp: Shows user-hostname stamp for identification

User enumeration process:
- Parses /etc/passwd to extract user information
- Filters out system accounts when appropriate
- Checks SSH access permissions when requested
- Generates user-hostname stamps for identification

SSH access detection includes:
- Users with valid shell access
- Users with SSH key configurations
- Users with SSH directory permissions
- Users with authorized_keys files`,
	Example: `  # List all system users
  eos read users
  
  # List only users with SSH access
  eos read users --ssh-only
  
  # Get user-hostname stamp
  eos read users --stamp
  
  # Example output for all users:
  # - System account enumeration
  # - User ID and group information
  # - Home directory status
  # - Shell configuration
  
  # Example output for SSH users:
  # - SSH-enabled user accounts
  # - SSH key availability
  # - SSH configuration status`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Reading user information")

		sshOnly, _ := cmd.Flags().GetBool("ssh-only")
		showStamp, _ := cmd.Flags().GetBool("stamp")

		// Show user-hostname stamp if requested
		if showStamp {
			stamp, err := users.GetUserHostnameStamp()
			if err != nil {
				logger.Error("Failed to get user-hostname stamp", zap.Error(err))
				return fmt.Errorf("failed to get user-hostname stamp: %w", err)
			}
			logger.Info("User-hostname stamp", zap.String("stamp", stamp))
			return nil
		}

		// Show users with SSH access if requested
		if sshOnly {
			sshUsers, err := users.ListUsersWithSSHAccess(rc)
			if err != nil {
				logger.Error("Failed to list users with SSH access", zap.Error(err))
				return fmt.Errorf("failed to list users with SSH access: %w", err)
			}

			logger.Info("Users with SSH access:")
			for _, user := range sshUsers {
				logger.Info("SSH user", zap.String("username", user))
			}
			return nil
		}

		// Show all system users
		logger.Info("Reading all system users...")
		allUsers, err := getSystemUsers(rc)
		if err != nil {
			logger.Error("Error reading users", zap.Error(err))
			return err
		}

		logger.Info("Current system users:")
		for _, user := range allUsers {
			logger.Info("System user", zap.String("username", user))
		}

		return nil
	}),
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// getSystemUsers reads the /etc/passwd file and returns a list of usernames
func getSystemUsers(rc *eos_io.RuntimeContext) ([]string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("failed to open /etc/passwd: %w", err)
	}
	defer shared.SafeClose(rc.Ctx, file)

	var users []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue // Skip comments and empty lines
		}
		parts := strings.Split(line, ":")
		if len(parts) > 0 {
			users = append(users, parts[0]) // Username is the first field
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read /etc/passwd: %w", err)
	}

	return users, nil
}

// init registers subcommands for the read command
func init() {
	ReadCmd.AddCommand(InspectUsersCmd)

	// Add flags for SSH and stamp functionality
	InspectUsersCmd.Flags().Bool("ssh-only", false, "List only users with SSH access")
	InspectUsersCmd.Flags().Bool("stamp", false, "Show user-hostname stamp")
}
