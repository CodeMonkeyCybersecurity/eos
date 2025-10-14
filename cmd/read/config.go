// cmd/read/config.go

package read

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
	Short: "Read a configuration value from Consul KV",
	Long: `Read EOS configuration values stored in Consul KV.

Configuration values are stored in Consul under the 'eos/config/' prefix.
This allows sharing configuration across servers and eliminates repetitive prompts.

Examples:
  # Read Authentik URL
  eos read config authentik/url

  # Read database connection string
  eos read config database/connection_string`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		key := args[0]

		client, err := consul_config.NewClient(rc.Ctx)
		if err != nil {
			return fmt.Errorf("consul not available: %w\n\nEnsure Consul is running and CONSUL_HTTP_ADDR is set correctly", err)
		}

		value, found, err := client.Get(rc.Ctx, key)
		if err != nil {
			return fmt.Errorf("failed to get config: %w", err)
		}

		if !found {
			logger.Info("Configuration key not found", zap.String("key", key))
			return nil
		}

		logger.Info("Configuration value",
			zap.String("key", key),
			zap.String("value", value))

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(configCmd)
}
