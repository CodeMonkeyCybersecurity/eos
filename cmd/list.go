package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var listUsersCmd = &cobra.Command{
	Use:   "list",
	Short: "List user accounts on the system",
	Long:  `This command lists all user accounts available on the system by reading the /etc/passwd file.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Read the /etc/passwd file
		file, err := os.Open("/etc/passwd")
		if err != nil {
			fmt.Printf("Error reading /etc/passwd: %s\n", err)
			return
		}
		defer file.Close()

		fmt.Println("User accounts on this system:")
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			// Each line is in the format: username:x:uid:gid:comment:home:shell
			parts := strings.Split(line, ":")
			if len(parts) > 0 {
				fmt.Println("- " + parts[0]) // Print the username
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading file: %s\n", err)
		}
	},
}

func init() {
	usersCmd.AddCommand(listUsersCmd)
}
