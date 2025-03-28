// cmd/delphi/inspect/users.go
package inspect

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
)

var UsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List Wazuh users and their IDs",
	Long:  "Fetches and displays all Wazuh users along with their associated user IDs from the Delphi (Wazuh) API.",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()

		cfg, err := config.LoadDelphiConfig()
		if err != nil {
			log.Fatal("Failed to load Delphi config", zap.Error(err))
		}

		users, err := config.GetAllUsers(cfg)
		if err != nil {
			log.Fatal("Failed to fetch users", zap.Error(err))
		}

		fmt.Println("Wazuh Users:")
		for _, user := range users {
			fmt.Printf("• %s (ID: %s)\n", user.Username, user.ID)
		}
	},
}

func init() {
	InspectCmd.AddCommand(UsersCmd)
}
