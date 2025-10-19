// cmd/sync/consul.go
package sync

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/sync/connectors"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
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

  # Force reconfiguration even if already joined
  eos sync consul --nodes vhost7 --force

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
	ConsulSyncCmd.Flags().BoolVar(&consulForce, "force", false,
		"Force reconfiguration even if already joined")
	ConsulSyncCmd.Flags().BoolVar(&consulSkipBackup, "skip-backup", false,
		"Skip configuration backup (use with caution)")

	// Add the consul command to the sync root
	SyncCmd.AddCommand(ConsulSyncCmd)
}

// TODO: refactor
var (
	consulDryRun     bool
	consulForce      bool
	consulSkipBackup bool
	consulNodes      []string
)
// TODO: refactor
func runConsulSync(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get node names from --nodes flag
	nodeNames := consulNodes

	if len(nodeNames) == 0 {
		return eos_err.NewUserError(
			"No nodes specified. Please specify at least one node.\n\n" +
				"Examples:\n" +
				"  eos sync consul --nodes vhost7\n" +
				"  eos sync consul --nodes vhost7 vhost11 vhost15\n\n" +
				"Use --nodes followed by one or more hostnames.")
	}

	logger.Info("Starting Consul cluster synchronization over Tailscale",
		zap.Strings("target_nodes", nodeNames),
		zap.Bool("dry_run", consulDryRun))

	// Use the Consul-Tailscale connector
	connector, err := connectors.NewConsulTailscaleConnector(rc, nodeNames)
	if err != nil {
		return eos_err.NewUserError("Failed to initialize Consul-Tailscale connector: %v", err)
	}

	config := &connectors.ConsulTailscaleSyncConfig{
		TargetNodes: nodeNames,
		DryRun:      consulDryRun,
		Force:       consulForce,
		SkipBackup:  consulSkipBackup,
	}

	// Execute sync
	if err := connector.Sync(rc, config); err != nil {
		logger.Error("Consul synchronization failed", zap.Error(err))
		return err
	}

	logger.Info("================================================================================")
	logger.Info("Consul cluster synchronization completed successfully")
	logger.Info("================================================================================")
	logger.Info("",
		zap.Strings("joined_nodes", nodeNames))
	logger.Info("")
	logger.Info("This Consul node is now part of the cluster")
	logger.Info("")
	logger.Info("Verify with:")
	logger.Info("  consul members")
	logger.Info("  consul catalog services")
	logger.Info("")
	logger.Info("Code Monkey Cybersecurity - 'Cybersecurity. With humans.'")
	logger.Info("================================================================================")

	return nil
}
// TODO: refactor
// TailscaleStatus represents the JSON output from `tailscale status --json`
type TailscaleStatus struct {
	TailscaleIPs []string                     `json:"TailscaleIPs"`
	Self         TailscalePeer                `json:"Self"`
	Peer         map[string]TailscalePeer     `json:"Peer"`
}
// TODO: refactor
type TailscalePeer struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
}
// TODO: refactor
// GetTailscaleStatus returns the current Tailscale status
func GetTailscaleStatus(rc *eos_io.RuntimeContext) (*TailscaleStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if tailscale is installed
	if _, err := exec.LookPath("tailscale"); err != nil {
		return nil, eos_err.NewUserError(
			"Tailscale is not installed. Please install Tailscale first:\n" +
				"  sudo eos create tailscale\n" +
				"  sudo tailscale up")
	}

	// Get status as JSON
	cmd := exec.Command("tailscale", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get Tailscale status: %w\n"+
			"Is Tailscale authenticated? Run: sudo tailscale up", err)
	}

	var status TailscaleStatus
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, fmt.Errorf("failed to parse Tailscale status: %w", err)
	}

	logger.Debug("Got Tailscale status",
		zap.Int("peer_count", len(status.Peer)),
		zap.String("self_hostname", status.Self.HostName))

	return &status, nil
}
// TODO: refactor
// FindPeerByHostname finds a Tailscale peer by hostname (case-insensitive, fuzzy)
func FindPeerByHostname(status *TailscaleStatus, hostname string) (*TailscalePeer, error) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	// Try exact hostname match first
	for _, peer := range status.Peer {
		peerHostname := strings.ToLower(peer.HostName)
		if peerHostname == hostname {
			return &peer, nil
		}

		// Also try without spaces and special chars
		peerSimple := strings.ReplaceAll(peerHostname, " ", "")
		peerSimple = strings.ReplaceAll(peerSimple, "-", "")
		hostnameSimple := strings.ReplaceAll(hostname, " ", "")
		hostnameSimple = strings.ReplaceAll(hostnameSimple, "-", "")

		if peerSimple == hostnameSimple {
			return &peer, nil
		}

		// Try DNS name match
		if strings.HasPrefix(strings.ToLower(peer.DNSName), hostname+".") {
			return &peer, nil
		}
	}

	// Build helpful error message
	availableHosts := make([]string, 0, len(status.Peer))
	for _, peer := range status.Peer {
		availableHosts = append(availableHosts, peer.HostName)
	}

	return nil, fmt.Errorf("node '%s' not found on Tailscale network\n"+
		"Available nodes:\n  - %s\n\n"+
		"Make sure the remote node is:\n"+
		"  1. Running Tailscale (sudo tailscale up)\n"+
		"  2. Connected to the same Tailnet\n"+
		"  3. Online and accessible",
		hostname, strings.Join(availableHosts, "\n  - "))
}
