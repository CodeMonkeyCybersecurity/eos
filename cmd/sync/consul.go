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
	consulDryRun          bool
	consulSkipBackup      bool
	consulNodes           []string
	consulACLToken        string
	consulAllowOffline    bool
	consulForceNoPreserve bool
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
	ConsulSyncCmd.Flags().StringVar(&consulACLToken, "acl-token", "",
		"ACL token for Consul API access (or set CONSUL_HTTP_TOKEN)")
	ConsulSyncCmd.Flags().BoolVar(&consulAllowOffline, "allow-offline", true,
		"Allow adding offline nodes to retry_join (default: true)")
	ConsulSyncCmd.Flags().BoolVar(&consulForceNoPreserve, "no-preserve-ips", false,
		"Do NOT preserve non-Tailscale IPs (dangerous in mixed networks)")

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

	// Create enhanced V2 configuration with all P0-P3 fixes
	config := consul.DefaultNodeJoinConfigV2()
	config.TargetNodes = consulNodes
	config.DryRun = consulDryRun
	config.SkipBackup = consulSkipBackup
	config.ACLToken = consulACLToken
	config.AllowOffline = consulAllowOffline
	config.PreserveNonTailscale = !consulForceNoPreserve

	// Execute enhanced node join operation (V2 with all fixes)
	result, err := consul.JoinNodesV2(rc, config)
	if err != nil {
		return err
	}

	// Display enhanced results
	displayNodeJoinResultsV2(logger, result)

	return nil
}

// displayNodeJoinResultsV2 displays the enhanced results with P0-P3 status
func displayNodeJoinResultsV2(logger otelzap.LoggerWithCtx, result *consul.NodeJoinResultV2) {
	logger.Info("================================================================================")

	if !result.ConfigChanged {
		logger.Info("Consul cluster configuration already correct - no changes made")
		logger.Info("================================================================================")
		logger.Info("")
		logger.Info("✓ Configuration is idempotent - already properly configured")
		logger.Info("✓ No restart needed - Consul continues running")
		logger.Info("")
		logger.Info("Current Configuration:")
		logger.Info("  Hostname:     " + result.LocalNode.Hostname)
		logger.Info("  Tailscale IP: " + result.LocalNode.TailscaleIP)
		if len(result.ClusterMembers) > 0 {
			logger.Info(fmt.Sprintf("  Cluster size: %d members", len(result.ClusterMembers)))
		}
		logger.Info("")
		logger.Info("No action required!")
		logger.Info("================================================================================")
		return
	}

	logger.Info("Consul cluster join completed successfully")
	logger.Info("================================================================================")
	logger.Info("")

	// Show what changed
	logger.Info("Changes Applied:")
	logger.Info("  ✓ Configuration updated")
	logger.Info("  ✓ Consul service restarted")
	logger.Info("  ✓ Cluster membership verified")
	logger.Info("")

	logger.Info("Local Node:")
	logger.Info("  Hostname:     " + result.LocalNode.Hostname)
	logger.Info("  Tailscale IP: " + result.LocalNode.TailscaleIP)
	logger.Info("")

	logger.Info("Joined Nodes:")
	for i, node := range result.JoinedNodes {
		status := "online"
		if !node.Online {
			status = "offline (will join when online)"
		}
		logger.Info(fmt.Sprintf("  [%d] %s", i+1, node.Hostname))
		logger.Info("      Tailscale IP: " + node.TailscaleIP)
		logger.Info("      Status:       " + status)
	}
	logger.Info("")

	// Show mixed network warning if applicable
	if result.MixedNetwork {
		logger.Info("⚠ Mixed Network Topology Detected:")
		logger.Info(fmt.Sprintf("  Tailscale members:     %d", len(result.JoinedNodes)))
		if len(result.PreservedIPs) > 0 {
			logger.Info(fmt.Sprintf("  Non-Tailscale members: %d (preserved)", len(result.PreservedIPs)))
			logger.Info("  Preserved IPs: " + fmt.Sprintf("%v", result.PreservedIPs))
		}
		logger.Info("")
	}

	if len(result.ClusterMembers) > 0 {
		logger.Info("Cluster Members:")
		for _, member := range result.ClusterMembers {
			logger.Info("  • " + member)
		}
		logger.Info("")
	}

	if result.ACLEnabled {
		logger.Info("✓ ACL Mode: Enabled (token configured)")
		logger.Info("")
	}

	if result.BackupPath != "" {
		logger.Info("Backup saved: " + result.BackupPath)
		logger.Info("")
	}

	logger.Info("Next Steps:")
	logger.Info("  • Verify cluster: consul members")
	logger.Info("  • Check health: sudo eos read consul --health")
	logger.Info("  • View logs: sudo journalctl -u consul -f")
	if result.MixedNetwork {
		logger.Info("  • Review network topology: Consider migrating all nodes to Tailscale")
	}
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")
}
