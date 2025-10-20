// cmd/list/ceph.go
package list

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/servicestatus"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO: refactor

var (
	cephOutputFormat string
)

var cephCmd = &cobra.Command{
	Use:   "ceph",
	Short: "Check Ceph cluster status, health, and configuration",
	Long: `Comprehensive status check for Ceph distributed storage cluster.

This command validates:
- Installation and binary presence
- Cluster health (HEALTH_OK, HEALTH_WARN, HEALTH_ERR)
- MON/MGR/OSD daemon status
- Storage capacity and usage
- Network configuration
- CephFS and RBD integrations
- Quorum and cluster membership

The command provides detailed diagnostics to quickly identify any issues
with your Ceph cluster deployment.

EXAMPLES:
  # Full cluster status check
  sudo eos list ceph

  # JSON output for automation/monitoring
  sudo eos list ceph --format json

  # YAML output
  sudo eos list ceph --format yaml

  # Short one-line summary
  sudo eos list ceph --format short

  # Alias commands (same functionality)
  sudo eos ls ceph
  sudo eos check ceph`,

	RunE: eos_cli.Wrap(runCephCheck),
}

func init() {
	cephCmd.Flags().StringVarP(&cephOutputFormat, "format", "f", "text",
		"Output format: text, json, yaml, short")

	ListCmd.AddCommand(cephCmd)
}

// TODO: refactor
func runCephCheck(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Ceph status check")

	// Create status provider
	provider := servicestatus.NewCephStatusProvider()

	// Get comprehensive status
	status, err := provider.GetStatus(rc)
	if err != nil {
		logger.Error("Failed to get Ceph status", zap.Error(err))
		return err
	}

	// Determine output format
	format := servicestatus.FormatText
	switch cephOutputFormat {
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
		logger.Info("Ceph status check completed - cluster is healthy")
	} else if status.HasWarnings() {
		logger.Warn("Ceph status check completed - cluster has warnings")
	} else {
		logger.Error("Ceph status check completed - cluster has errors")
	}

	return nil
}
