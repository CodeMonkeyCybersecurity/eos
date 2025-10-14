// cmd/list/config.go

package list

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
	Use:   "config [prefix]",
	Short: "List configuration values from Consul KV",
	Long: `List EOS configuration values stored in Consul KV.

Configuration values are stored in Consul under the 'eos/config/' prefix.
You can optionally provide a prefix to filter the results.

Examples:
  # List all configuration values
  eos list config

  # List all Authentik configs
  eos list config authentik

  # List all database configs
  eos list config database`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		prefix := ""
		if len(args) > 0 {
			prefix = args[0]
		}

		client, err := consul_config.NewClient(rc.Ctx)
		if err != nil {
			return fmt.Errorf("consul not available: %w\n\nEnsure Consul is running and CONSUL_HTTP_ADDR is set correctly", err)
		}

		configs, err := client.List(rc.Ctx, prefix)
		if err != nil {
			return fmt.Errorf("failed to list configs: %w", err)
		}

		if len(configs) == 0 {
			logger.Info("No configuration values found", zap.String("prefix", prefix))
			return nil
		}

		logger.Info("Configuration values",
			zap.String("prefix", prefix),
			zap.Int("count", len(configs)))

		for key, value := range configs {
			logger.Info("", zap.String(key, value))
		}

		return nil
	}),
}

func init() {
	ListCmd.AddCommand(configCmd)
}
