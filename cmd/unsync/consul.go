// cmd/unsync/consul.go
package unsync

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	consulUnsyncDryRun     bool
	consulUnsyncSkipBackup bool
	consulUnsyncNodes      []string
	consulUnsyncACLToken   string
)

// ConsulUnsyncCmd handles removing Consul nodes from retry_join configuration
var ConsulUnsyncCmd = &cobra.Command{
	Use:   "consul --nodes <node1> [node2] [node3] ...",
	Short: "Remove nodes from Consul retry_join configuration",
	Long: `Remove specified nodes from THIS node's Consul retry_join configuration.

This command automatically:
  1. Resolves node hostnames to Tailscale IPs
  2. Removes matching IPs from retry_join configuration
  3. Backs up current configuration (unless --skip-backup)
  4. Updates and validates configuration
  5. Restarts Consul service
  6. Verifies cluster membership

Examples:
  # Remove vhost5 from retry_join
  eos unsync consul --nodes vhost5

  # Remove multiple nodes
  eos unsync consul --nodes vhost5 vhost7 vhost11

  # Preview changes without applying
  eos unsync consul --nodes vhost5 --dry-run

Requirements:
  - Tailscale must be installed and authenticated
  - Consul must be installed and running
  - Nodes to remove should be visible on Tailscale network (or use IPs directly)

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(runConsulUnsync),
}

func init() {
	ConsulUnsyncCmd.Flags().StringSliceVar(&consulUnsyncNodes, "nodes", []string{},
		"Hostnames of Consul nodes to remove from retry_join (space-separated)")
	ConsulUnsyncCmd.Flags().BoolVar(&consulUnsyncDryRun, "dry-run", false,
		"Preview changes without applying them")
	ConsulUnsyncCmd.Flags().BoolVar(&consulUnsyncSkipBackup, "skip-backup", false,
		"Skip configuration backup (use with caution)")
	ConsulUnsyncCmd.Flags().StringVar(&consulUnsyncACLToken, "acl-token", "",
		"ACL token for Consul API access (or set CONSUL_HTTP_TOKEN)")

	// Register as subcommand of unsync
	UnsyncCmd.AddCommand(ConsulUnsyncCmd)
}

func runConsulUnsync(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate we have at least one target node
	if len(consulUnsyncNodes) == 0 {
		return eos_err.NewUserError(
			"No nodes specified. Please specify at least one node to remove.\n\n" +
				"Examples:\n" +
				"  eos unsync consul --nodes vhost5\n" +
				"  eos unsync consul --nodes vhost5 vhost7 vhost11\n\n" +
				"Use --nodes followed by one or more hostnames.")
	}

	logger.Info("Starting Consul node removal from retry_join configuration",
		zap.Strings("target_nodes", consulUnsyncNodes),
		zap.Bool("dry_run", consulUnsyncDryRun))

	// Create configuration for node removal
	config := consul.DefaultNodeUnjoinConfig()
	config.TargetNodes = consulUnsyncNodes
	config.DryRun = consulUnsyncDryRun
	config.SkipBackup = consulUnsyncSkipBackup
	config.ACLToken = consulUnsyncACLToken

	// Execute node removal operation
	result, err := consul.UnjoinNodes(rc, config)
	if err != nil {
		return err
	}

	// Display results
	displayNodeUnjoinResults(logger, result)

	return nil
}

// displayNodeUnjoinResults displays the results of node removal
func displayNodeUnjoinResults(logger otelzap.LoggerWithCtx, result *consul.NodeUnjoinResult) {
	logger.Info("================================================================================")

	if !result.ConfigChanged {
		logger.Info("Consul configuration already correct - nodes not in retry_join")
		logger.Info("================================================================================")
		logger.Info("")
		logger.Info("✓ Configuration is idempotent - nodes already removed or never existed")
		logger.Info("✓ No restart needed - Consul continues running")
		logger.Info("")
		logger.Info("Current Configuration:")
		logger.Info("  Hostname:     " + result.LocalNode.Hostname)
		logger.Info("  Tailscale IP: " + result.LocalNode.TailscaleIP)
		if len(result.RemainingRetryJoin) > 0 {
			logger.Info(fmt.Sprintf("  retry_join:   %v", result.RemainingRetryJoin))
		} else {
			logger.Info("  retry_join:   (empty)")
		}
		logger.Info("")
		logger.Info("No action required!")
		logger.Info("================================================================================")
		return
	}

	logger.Info("Consul node removal completed successfully")
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

	logger.Info("Removed Nodes:")
	for i, node := range result.RemovedNodes {
		logger.Info(fmt.Sprintf("  [%d] %s", i+1, node.Hostname))
		logger.Info("      Tailscale IP: " + node.TailscaleIP)
	}
	logger.Info("")

	if len(result.RemainingRetryJoin) > 0 {
		logger.Info("Remaining retry_join configuration:")
		for i, ip := range result.RemainingRetryJoin {
			logger.Info(fmt.Sprintf("  [%d] %s", i+1, ip))
		}
		logger.Info("")
	} else {
		logger.Info("⚠ Warning: retry_join is now empty - this node is no longer configured to join any cluster")
		logger.Info("")
	}

	if len(result.ClusterMembers) > 0 {
		logger.Info("Current Cluster Members:")
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
	logger.Info("  • Check health: sudo eos read consul --health")
	logger.Info("  • View logs: sudo journalctl -u consul -f")
	if len(result.RemainingRetryJoin) == 0 {
		logger.Info("  • Consider re-adding nodes or running a fresh sync if needed")
	}
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")
}
