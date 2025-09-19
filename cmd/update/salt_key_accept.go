// cmd/update/salt_key_accept.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var consulNodeJoinCmd = &cobra.Command{
	Use:     "consul-node-join [node-address]",
	Aliases: []string{"join-node", "consul-join"},
	Short:   "Join a node to the Consul cluster",
	Long: `Join a node to the Consul cluster for service discovery and coordination.

This command helps nodes join the Consul cluster, enabling them to participate
in service discovery, health checking, and distributed coordination. This is
a security-critical operation that should only be performed for trusted nodes.

Examples:
  eos update consul-node-join 192.168.1.10    # Join specific node
  eos update consul-node-join --wan            # Join via WAN
  eos update consul-node-join --retry-join     # Enable retry join

Security Notice:
  - Only join trusted nodes to the cluster
  - Verify node identity before joining
  - Use proper ACL tokens for authentication
  - Consider using --dry-run to preview changes`,

	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse node address from args
		var nodeAddress string
		if len(args) > 0 {
			nodeAddress = args[0]
		}

		// Parse flags
		wan, _ := cmd.Flags().GetBool("wan")
		retryJoin, _ := cmd.Flags().GetBool("retry-join")
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		// Validate input
		if nodeAddress == "" {
			return fmt.Errorf("must specify node address")
		}

		logger.Info("Joining node to Consul cluster",
			zap.String("node_address", nodeAddress),
			zap.Bool("wan", wan),
			zap.Bool("retry_join", retryJoin),
			zap.Bool("force", force),
			zap.Bool("dry_run", dryRun))

		if dryRun {
			logger.Info("terminal prompt: DRY RUN: Would join node to Consul cluster")
			logger.Info("terminal prompt:   Node Address:", zap.String("node_address", nodeAddress))
			if wan {
				logger.Info("terminal prompt:   Join Type: WAN")
			} else {
				logger.Info("terminal prompt:   Join Type: LAN")
			}
			return nil
		}

		// Security confirmation for node join
		if !force {
			logger.Info("terminal prompt: WARNING: This will join node to cluster. Continue? [y/N]: ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				// If we can't read user input, default to cancel for security
				return fmt.Errorf("failed to read user confirmation: %w", err)
			}
			if response != "y" && response != "Y" && response != "yes" {
				return fmt.Errorf("operation cancelled by user")
			}
		}

		// TODO: Implement Consul node join functionality
		logger.Info("terminal prompt: Consul node join not yet implemented")
		logger.Info("terminal prompt: Node Address:", zap.String("node_address", nodeAddress))
		logger.Info("terminal prompt: Use 'consul join" + nodeAddress + "' directly for now")
		return fmt.Errorf("Consul node join integration pending - use consul CLI directly")
	}),
}

func init() {
	consulNodeJoinCmd.Flags().Bool("wan", false, "Join via WAN")
	consulNodeJoinCmd.Flags().Bool("retry-join", false, "Enable retry join")
	consulNodeJoinCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompts")
	consulNodeJoinCmd.Flags().Bool("dry-run", false, "Show what would be joined without making changes")

	UpdateCmd.AddCommand(consulNodeJoinCmd)
}
