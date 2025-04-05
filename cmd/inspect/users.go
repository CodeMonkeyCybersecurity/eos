// cmd/inspect/users.go
package inspect

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// readUsersCmd represents the command to read users
var InspectUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Retrieve information about system users",
	Long: `This command retrieves a list of all system users on the current machine
by reading the /etc/passwd file.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reading users...")
		users, err := getSystemUsers()
		if err != nil {
			fmt.Printf("Error reading users: %v\n", err)
			return
		}

		fmt.Println("Current users:")
		for _, user := range users {
			fmt.Println(user)
		}
	},
}

// getSystemUsers reads the /etc/passwd file and returns a list of usernames
func getSystemUsers() ([]string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("failed to open /etc/passwd: %w", err)
	}
	defer file.Close()

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
	InspectCmd.AddCommand(InspectUsersCmd)
}
