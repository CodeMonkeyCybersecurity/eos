// cmd/sync/consul.go
package sync

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	consulDryRun     bool
	consulSkipBackup bool
	consulNodes      []string
)

// ConsulSyncCmd handles Consul cluster synchronization over Tailscale
var ConsulSyncCmd = &cobra.Command{
	Use:   "consul --nodes <node1> [node2] [node3] ...",
	Short: "Join this Consul node to other nodes over Tailscale",
	Long: `Join this Consul node to one or more Consul nodes over Tailscale network.

This command automatically:
  1. Discovers remote nodes on Tailscale network by hostname
  2. Configures THIS node to use its Tailscale IP for Consul
  3. Adds remote nodes as retry_join targets
  4. Reconfigures and restarts Consul
  5. Verifies cluster membership

Examples:
  # Join THIS node to vhost7's Consul cluster
  eos sync consul --nodes vhost7

  # Join THIS node to multiple Consul nodes
  eos sync consul --nodes vhost7 vhost11 vhost15

  # Preview changes without applying
  eos sync consul --nodes vhost7 vhost11 --dry-run

Requirements:
  - Tailscale must be installed and authenticated
  - Consul must be installed on all nodes
  - Remote nodes must be visible on Tailscale network

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(runConsulSync),
}

func init() {
	ConsulSyncCmd.Flags().StringSliceVar(&consulNodes, "nodes", []string{},
		"Hostnames of Consul nodes to join (space-separated)")
	ConsulSyncCmd.Flags().BoolVar(&consulDryRun, "dry-run", false,
		"Preview changes without applying them")
	ConsulSyncCmd.Flags().BoolVar(&consulSkipBackup, "skip-backup", false,
		"Skip configuration backup (use with caution)")

	// Register as subcommand of sync
	SyncCmd.AddCommand(ConsulSyncCmd)
}

func runConsulSync(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate we have at least one target node
	if len(consulNodes) == 0 {
		return eos_err.NewUserError(
			"No nodes specified. Please specify at least one node.\n\n" +
				"Examples:\n" +
				"  eos sync consul --nodes vhost7\n" +
				"  eos sync consul --nodes vhost7 vhost11 vhost15\n\n" +
				"Use --nodes followed by one or more hostnames.")
	}

	logger.Info("Starting Consul cluster synchronization over Tailscale",
		zap.Strings("target_nodes", consulNodes),
		zap.Bool("dry_run", consulDryRun))

	// Create configuration (business logic in pkg/consul/node_join.go)
	config := consul.DefaultNodeJoinConfig()
	config.TargetNodes = consulNodes
	config.DryRun = consulDryRun
	config.SkipBackup = consulSkipBackup

	// Execute node join operation
	result, err := consul.JoinNodes(rc, config)
	if err != nil {
		return err
	}

	// Display results
	displayNodeJoinResults(logger, result)

	return nil
}

// displayNodeJoinResults displays the results of node join operation
func displayNodeJoinResults(logger otelzap.LoggerWithCtx, result *consul.NodeJoinResult) {
	logger.Info("================================================================================")
	logger.Info("Consul cluster join completed successfully")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Local Node:")
	logger.Info("  Hostname:     " + result.LocalNode.Hostname)
	logger.Info("  Tailscale IP: " + result.LocalNode.TailscaleIP)
	logger.Info("")

	logger.Info("Joined Nodes:")
	for i, node := range result.JoinedNodes {
		logger.Info(fmt.Sprintf("  [%d] %s", i+1, node.Hostname))
		logger.Info("      Tailscale IP: " + node.TailscaleIP)
		logger.Info("      Status:       online")
	}
	logger.Info("")

	if len(result.ClusterMembers) > 0 {
		logger.Info("Cluster Members:")
		for _, member := range result.ClusterMembers {
			logger.Info("  • " + member)
		}
		logger.Info("")
	}

	if result.BackupPath != "" {
		logger.Info("Backup saved: " + result.BackupPath)
		logger.Info("")
	}

	logger.Info("Next Steps:")
	logger.Info("  • Verify cluster: consul members")
	logger.Info("  • Check logs: sudo journalctl -u consul -f")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")
}
