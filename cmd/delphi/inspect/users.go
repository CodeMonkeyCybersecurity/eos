// cmd/delphi/inspect/users.go
package inspect

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
)

var UsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List Wazuh users and their IDs",
	Long:  "Fetches and displays all Wazuh users along with their associated user IDs from the Delphi (Wazuh) API.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := delphi.ReadConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to load Delphi config", zap.Error(err))
		}

		users, err := delphi.GetAllUsers(rc, cfg)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to fetch users", zap.Error(err))
		}

		fmt.Println("Wazuh Users:")
		for _, user := range users {
			fmt.Printf("• %s (ID: %d)\n", user.Username, user.ID)
		}
		return nil
	}),
}

func init() {
	InspectCmd.AddCommand(UsersCmd)
}
