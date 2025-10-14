// cmd/delete/config.go

package delete

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul_config"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var configCmd = &cobra.Command{
	Use:   "config <key>",
	Short: "Delete a configuration value from Consul KV",
	Long: `Delete EOS configuration values from Consul KV.

Configuration values are stored in Consul under the 'eos/config/' prefix.
This command removes a specific configuration key from Consul.

Examples:
  # Delete Authentik URL
  eos delete config authentik/url

  # Delete database connection string
  eos delete config database/connection_string`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		key := args[0]

		client, err := consul_config.NewClient(rc.Ctx)
		if err != nil {
			return fmt.Errorf("consul not available: %w\n\nEnsure Consul is running and CONSUL_HTTP_ADDR is set correctly", err)
		}

		if err := client.Delete(rc.Ctx, key); err != nil {
			return fmt.Errorf("failed to delete config: %w", err)
		}

		logger.Info("Configuration value deleted", zap.String("key", key))
		return nil
	}),
}

func init() {
	DeleteCmd.AddCommand(configCmd)
}
