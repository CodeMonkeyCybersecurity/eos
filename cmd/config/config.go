// cmd/config/config.go

package config

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul_config"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigCmd manages EOS configuration stored in Consul KV
var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage EOS configuration stored in Consul KV",
	Long: `Manage EOS configuration values stored in Consul KV.

Configuration values are stored in Consul under the 'eos/config/' prefix.
This allows sharing configuration across servers and eliminates repetitive prompts.

Examples:
  # Get Authentik URL
  eos config get authentik/url

  # Set Authentik URL
  eos config set authentik/url https://auth.example.com

  # List all Authentik configs
  eos config list authentik

  # Delete a config value
  eos config delete authentik/url`,
}

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value from Consul",
	Args:  cobra.ExactArgs(1),
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

var setCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value in Consul",
	Args:  cobra.ExactArgs(2),
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

var deleteCmd = &cobra.Command{
	Use:   "delete <key>",
	Short: "Delete a configuration value from Consul",
	Args:  cobra.ExactArgs(1),
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

var listCmd = &cobra.Command{
	Use:   "list [prefix]",
	Short: "List configuration values from Consul",
	Args:  cobra.MaximumNArgs(1),
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
	ConfigCmd.AddCommand(getCmd)
	ConfigCmd.AddCommand(setCmd)
	ConfigCmd.AddCommand(deleteCmd)
	ConfigCmd.AddCommand(listCmd)
}
