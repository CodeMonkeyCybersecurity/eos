// cmd/read/ceph.go
package read

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cephfs"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/servicestatus"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	cephOutputFormat string
	cephMonHosts     []string
	cephUser         string
	cephConfigFile   string
	cephUseConsul    bool
	cephVolumeName   string // For listing snapshots of specific volume
)

var readCephCmd = &cobra.Command{
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
  sudo eos read ceph
  sudo eos enum ceph

  # JSON output for automation/monitoring
  sudo eos read ceph --format json

  # YAML output
  sudo eos read ceph --format yaml

  # Short one-line summary
  sudo eos read ceph --format short`,

	RunE: eos_cli.Wrap(runReadCephCheck),
}

func init() {
	readCephCmd.Flags().StringVarP(&cephOutputFormat, "format", "f", "text",
		"Output format: text, json, yaml, short")

	// Add subcommands for SDK-based operations
	readCephCmd.AddCommand(readCephVolumesCmd)
	readCephCmd.AddCommand(readCephSnapshotsCmd)
	readCephCmd.AddCommand(readCephPoolsCmd)

	// Volumes subcommand flags
	readCephVolumesCmd.Flags().StringSliceVar(&cephMonHosts, "monitors", []string{}, "Ceph monitor addresses")
	readCephVolumesCmd.Flags().StringVar(&cephUser, "user", "admin", "Ceph user name")
	readCephVolumesCmd.Flags().StringVar(&cephConfigFile, "config", "", "Path to ceph.conf file")
	readCephVolumesCmd.Flags().BoolVar(&cephUseConsul, "use-consul", false, "Discover monitors from Consul")
	readCephVolumesCmd.Flags().StringVarP(&cephOutputFormat, "format", "f", "text", "Output format: text, json, yaml")

	// Snapshots subcommand flags
	readCephSnapshotsCmd.Flags().StringSliceVar(&cephMonHosts, "monitors", []string{}, "Ceph monitor addresses")
	readCephSnapshotsCmd.Flags().StringVar(&cephUser, "user", "admin", "Ceph user name")
	readCephSnapshotsCmd.Flags().StringVar(&cephConfigFile, "config", "", "Path to ceph.conf file")
	readCephSnapshotsCmd.Flags().BoolVar(&cephUseConsul, "use-consul", false, "Discover monitors from Consul")
	readCephSnapshotsCmd.Flags().StringVar(&cephVolumeName, "volume", "", "Volume to list snapshots for (required)")
	readCephSnapshotsCmd.Flags().StringVarP(&cephOutputFormat, "format", "f", "text", "Output format: text, json, yaml")
	readCephSnapshotsCmd.MarkFlagRequired("volume")

	// Pools subcommand flags
	readCephPoolsCmd.Flags().StringSliceVar(&cephMonHosts, "monitors", []string{}, "Ceph monitor addresses")
	readCephPoolsCmd.Flags().StringVar(&cephUser, "user", "admin", "Ceph user name")
	readCephPoolsCmd.Flags().StringVar(&cephConfigFile, "config", "", "Path to ceph.conf file")
	readCephPoolsCmd.Flags().BoolVar(&cephUseConsul, "use-consul", false, "Discover monitors from Consul")
	readCephPoolsCmd.Flags().StringVarP(&cephOutputFormat, "format", "f", "text", "Output format: text, json, yaml")
}

func runReadCephCheck(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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

// readCephVolumesCmd lists all CephFS volumes
var readCephVolumesCmd = &cobra.Command{
	Use:   "volumes",
	Short: "List all CephFS volumes",
	Long: `List all CephFS volumes with detailed information using the go-ceph SDK.

Examples:
  eos read ceph volumes
  eos enum ceph volumes
  eos read ceph volumes --format json
  eos read ceph volumes --use-consul`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Create Ceph client
		clientConfig := &cephfs.ClientConfig{
			MonHosts:      cephMonHosts,
			User:          cephUser,
			ConfigFile:    cephConfigFile,
			ConsulEnabled: cephUseConsul,
		}

		client, err := cephfs.NewCephClient(rc, clientConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize Ceph client: %w", err)
		}
		defer client.Close()

		// List volumes
		volumes, err := client.ListVolumes(rc)
		if err != nil {
			return fmt.Errorf("failed to list volumes: %w", err)
		}

		// Output based on format
		switch cephOutputFormat {
		case "json":
			data, _ := json.MarshalIndent(volumes, "", "  ")
			logger.Info(string(data))
		case "yaml":
			data, _ := yaml.Marshal(volumes)
			logger.Info(string(data))
		default:
			logger.Info("CephFS Volumes", zap.Int("count", len(volumes)))
			for _, vol := range volumes {
				logger.Info("Volume",
					zap.String("name", vol.Name),
					zap.Int64("size", vol.Size),
					zap.Int64("used", vol.UsedSize),
					zap.Strings("dataPools", vol.DataPools))
			}
		}

		return nil
	}),
}

// readCephSnapshotsCmd lists snapshots for a volume
var readCephSnapshotsCmd = &cobra.Command{
	Use:   "snapshots",
	Short: "List snapshots for a CephFS volume",
	Long: `List all snapshots for a specified CephFS volume.

Examples:
  eos read ceph snapshots --volume mydata
  eos enum ceph snapshots --volume mydata
  eos read ceph snapshots --volume mydata --format json`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Create Ceph client
		clientConfig := &cephfs.ClientConfig{
			MonHosts:      cephMonHosts,
			User:          cephUser,
			ConfigFile:    cephConfigFile,
			ConsulEnabled: cephUseConsul,
		}

		client, err := cephfs.NewCephClient(rc, clientConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize Ceph client: %w", err)
		}
		defer client.Close()

		// List snapshots
		snapshots, err := client.ListSnapshots(rc, cephVolumeName, "")
		if err != nil {
			return fmt.Errorf("failed to list snapshots: %w", err)
		}

		// Output based on format
		switch cephOutputFormat {
		case "json":
			data, _ := json.MarshalIndent(snapshots, "", "  ")
			logger.Info(string(data))
		case "yaml":
			data, _ := yaml.Marshal(snapshots)
			logger.Info(string(data))
		default:
			logger.Info("CephFS Snapshots",
				zap.String("volume", cephVolumeName),
				zap.Int("count", len(snapshots)))
			for _, snap := range snapshots {
				logger.Info("Snapshot",
					zap.String("name", snap.Name),
					zap.Time("created", snap.CreatedAt),
					zap.Int64("size", snap.Size),
					zap.Bool("protected", snap.Protected))
			}
		}

		return nil
	}),
}

// readCephPoolsCmd lists all Ceph pools
var readCephPoolsCmd = &cobra.Command{
	Use:   "pools",
	Short: "List all Ceph pools",
	Long: `List all Ceph pools with detailed information.

Examples:
  eos read ceph pools
  eos enum ceph pools
  eos read ceph pools --format json`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Create Ceph client
		clientConfig := &cephfs.ClientConfig{
			MonHosts:      cephMonHosts,
			User:          cephUser,
			ConfigFile:    cephConfigFile,
			ConsulEnabled: cephUseConsul,
		}

		client, err := cephfs.NewCephClient(rc, clientConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize Ceph client: %w", err)
		}
		defer client.Close()

		// List pools
		pools, err := client.ListPools(rc)
		if err != nil {
			return fmt.Errorf("failed to list pools: %w", err)
		}

		// Output based on format
		switch cephOutputFormat {
		case "json":
			data, _ := json.MarshalIndent(pools, "", "  ")
			logger.Info(string(data))
		case "yaml":
			data, _ := yaml.Marshal(pools)
			logger.Info(string(data))
		default:
			logger.Info("Ceph Pools", zap.Int("count", len(pools)))
			for _, pool := range pools {
				logger.Info("Pool",
					zap.String("name", pool.Name),
					zap.Int64("id", pool.ID),
					zap.Int("size", pool.Size),
					zap.String("type", pool.Type))
			}
		}

		return nil
	}),
}
