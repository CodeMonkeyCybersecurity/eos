// cmd/list/consul.go
package list

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/servicestatus"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	consulOutputFormat string
)

var consulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Check Consul installation, configuration, and operational status",
	Long: `Comprehensive status check for Consul service discovery and configuration.

This command validates:
- Installation and binary presence
- Service status and health
- Configuration validity
- Cluster membership and health
- Network endpoints
- Integrations with other services (e.g., Vault)

The command provides detailed diagnostics to quickly identify any issues
with your Consul deployment.

EXAMPLES:
  # Full status check
  sudo eos list consul

  # JSON output for automation
  sudo eos list consul --format json

  # YAML output
  sudo eos list consul --format yaml

  # Short one-line summary
  sudo eos list consul --format short`,

	RunE: eos_cli.Wrap(runConsulCheck),
}

func init() {
	consulCmd.Flags().StringVarP(&consulOutputFormat, "format", "f", "text",
		"Output format: text, json, yaml, short")

	ListCmd.AddCommand(consulCmd)
}

// TODO: refactor
func runConsulCheck(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Consul status check")

	// Create status provider
	provider := servicestatus.NewConsulStatusProvider()

	// Get comprehensive status
	status, err := provider.GetStatus(rc)
	if err != nil {
		logger.Error("Failed to get Consul status", zap.Error(err))
		return err
	}

	// Determine output format
	format := servicestatus.FormatText
	switch consulOutputFormat {
	case "json":
		format = servicestatus.FormatJSON
	case "yaml":
		format = servicestatus.FormatYAML
	case "short":
		format = servicestatus.FormatShort
	}

	// Display status
	logger.Info(status.Display(format))

	// Log summary
	if status.IsHealthy() {
		logger.Info("Consul status check completed - service is healthy")
	} else if status.HasWarnings() {
		logger.Warn("Consul status check completed - service has warnings")
	} else {
		logger.Error("Consul status check completed - service has errors")
	}

	return nil
}
