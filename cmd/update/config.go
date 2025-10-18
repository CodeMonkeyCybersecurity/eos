// cmd/update/config.go

package update

import (
	"fmt"

	consul_config "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var configCmd = &cobra.Command{
	Use:   "config <key> <value>",
	Short: "Update a configuration value in Consul KV",
	Long: `Update EOS configuration values stored in Consul KV.

Configuration values are stored in Consul under the 'eos/config/' prefix.
This allows sharing configuration across servers and eliminates repetitive prompts.

Examples:
  # Set Authentik URL
  eos update config authentik/url https://auth.example.com

  # Update database connection string
  eos update config database/connection_string postgresql://localhost/mydb`,
	Args: cobra.ExactArgs(2),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		key := args[0]
		value := args[1]

		client, err := consul_config.NewClient(rc.Ctx)
		if err != nil {
			return fmt.Errorf("consul not available: %w\n\nEnsure Consul is running and CONSUL_HTTP_ADDR is set correctly", err)
		}

		if err := client.Set(rc.Ctx, key, value); err != nil {
			return fmt.Errorf("failed to set config: %w", err)
		}

		logger.Info("Configuration value set successfully",
			zap.String("key", key),
			zap.String("value", value))

		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(configCmd)
}
