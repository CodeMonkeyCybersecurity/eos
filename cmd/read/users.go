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
	"github.com/spf13/cobra"
)

// readUsersCmd represents the command to read users
var InspectUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Retrieve information about system users",
	Long: `This command retrieves a list of all system users on the current machine
by reading the /etc/passwd file.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		fmt.Println("Reading users...")
		users, err := getSystemUsers(rc)
		if err != nil {
			fmt.Printf("Error reading users: %v\n", err)
			return (err)
		}

		fmt.Println("Current users:")
		for _, user := range users {
			fmt.Println(user)
		}
		return nil
	}),
}

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
}
