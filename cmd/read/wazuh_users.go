// cmd/wazuh/read/users.go
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
)

var ReadUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List Wazuh users and their IDs",
	Long:  "Fetches and displays all Wazuh users along with their associated user IDs from the Wazuh (Wazuh) API.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := wazuh.ReadConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to load Wazuh config", zap.Error(err))
		}

		users, err := wazuh.GetAllUsers(rc, cfg)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to fetch users", zap.Error(err))
		}

		otelzap.Ctx(rc.Ctx).Info("terminal prompt: Wazuh Users")
		for _, user := range users {
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: User", zap.String("username", user.Username), zap.Int("id", user.ID))
		}
		return nil
	}),
}

func init() {
	readWazuhCmd.AddCommand(ReadUsersCmd)
}
