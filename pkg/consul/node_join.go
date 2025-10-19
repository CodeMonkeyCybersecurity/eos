// pkg/consul/node_join.go
// Business logic for joining Consul nodes over Tailscale network

package consul

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/tailscale"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NodeJoinConfig contains configuration for Consul node joining
type NodeJoinConfig struct {
	TargetNodes []string
	DryRun      bool
	SkipBackup  bool
	ConfigPath  string // Default: /etc/consul.d/consul.hcl
}

// NodeJoinResult contains the result of a node join operation
type NodeJoinResult struct {
	Success        bool
	LocalNode      NodeInfo
	JoinedNodes    []NodeInfo
	BackupPath     string
	ClusterMembers []string
}

// NodeInfo represents information about a Consul node
type NodeInfo struct {
	Hostname     string
	TailscaleIP  string
	DNSName      string
	Online       bool
	ConsulMember bool
}

// DefaultNodeJoinConfig returns a NodeJoinConfig with sensible defaults
func DefaultNodeJoinConfig() *NodeJoinConfig {
	return &NodeJoinConfig{
		ConfigPath: "/etc/consul.d/consul.hcl",
		DryRun:     false,
		SkipBackup: false,
	}
}

// JoinNodes orchestrates joining Consul nodes over Tailscale network
// Follows Assess → Intervene → Evaluate pattern
func JoinNodes(rc *eos_io.RuntimeContext, config *NodeJoinConfig) (*NodeJoinResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul node join operation",
		zap.Strings("target_nodes", config.TargetNodes),
		zap.Bool("dry_run", config.DryRun))

	// ASSESS - Phase 1: Discover Tailscale network
	logger.Info("[1/6] Discovering Tailscale network...")
	tsClient, err := tailscale.NewClient(rc)
	if err != nil {
		return nil, err // Already user-friendly from tailscale.NewClient
	}

	status, err := tsClient.GetStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	myTailscaleIP, err := tsClient.GetSelfIP()
	if err != nil {
		return nil, fmt.Errorf("failed to get this node's Tailscale IP: %w", err)
	}

	localNode := NodeInfo{
		Hostname:    status.Self.HostName,
		TailscaleIP: myTailscaleIP,
		DNSName:     status.Self.DNSName,
		Online:      status.Self.Online,
	}

	logger.Info("Local node Tailscale configuration",
		zap.String("hostname", localNode.Hostname),
		zap.String("tailscale_ip", localNode.TailscaleIP))

	// ASSESS - Phase 2: Resolve target nodes
	logger.Info("[2/6] Resolving target nodes on Tailscale...")
	var joinedNodes []NodeInfo
	var retryJoinAddrs []string

	for _, nodeName := range config.TargetNodes {
		peer, err := tsClient.FindPeerByHostname(nodeName)
		if err != nil {
			return nil, err // Already has user-friendly error message
		}

		// Verify peer is online
		if err := tsClient.VerifyPeerOnline(peer); err != nil {
			return nil, err // Already has user-friendly error message
		}

		targetIP, err := tsClient.GetPeerIP(peer)
		if err != nil {
			return nil, fmt.Errorf("failed to get IP for node '%s': %w", nodeName, err)
		}

		nodeInfo := NodeInfo{
			Hostname:    peer.HostName,
			TailscaleIP: targetIP,
			DNSName:     peer.DNSName,
			Online:      peer.Online,
		}

		joinedNodes = append(joinedNodes, nodeInfo)
		retryJoinAddrs = append(retryJoinAddrs, targetIP)

		logger.Info("Resolved target node",
			zap.String("node", nodeName),
			zap.String("hostname", peer.HostName),
			zap.String("tailscale_ip", targetIP),
			zap.Bool("online", peer.Online))
	}

	// ASSESS - Phase 3: Backup existing Consul configuration
	var backupPath string
	if !config.SkipBackup && !config.DryRun {
		logger.Info("[3/6] Backing up Consul configuration...")
		backupPath = fmt.Sprintf("%s.backup.%d", config.ConfigPath, time.Now().Unix())

		if err := copyFile(config.ConfigPath, backupPath); err != nil {
			logger.Warn("Failed to backup configuration (non-critical)", zap.Error(err))
		} else {
			logger.Info("Configuration backed up", zap.String("backup", backupPath))
		}
	} else {
		logger.Info("[3/6] Skipping configuration backup")
	}

	// Return early if dry run
	if config.DryRun {
		logger.Info("[4/6] DRY RUN MODE - No changes will be made")
		logger.Info("Would configure Consul with:",
			zap.String("bind_addr", myTailscaleIP),
			zap.Strings("retry_join", retryJoinAddrs))

		return &NodeJoinResult{
			Success:     true,
			LocalNode:   localNode,
			JoinedNodes: joinedNodes,
		}, nil
	}

	// INTERVENE - Phase 4: Update Consul configuration
	logger.Info("[4/6] Updating Consul configuration...")

	existingConfig, err := os.ReadFile(config.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Consul config at %s: %w\n"+
			"Fix: Ensure Consul is installed with 'sudo eos create consul'",
			config.ConfigPath, err)
	}

	newConfig := UpdateConsulConfig(string(existingConfig), myTailscaleIP, retryJoinAddrs)

	if err := os.WriteFile(config.ConfigPath, []byte(newConfig), 0640); err != nil {
		return nil, fmt.Errorf("failed to write Consul config: %w", err)
	}

	logger.Info("Consul configuration updated",
		zap.String("config", config.ConfigPath))

	// INTERVENE - Phase 5: Restart Consul service
	logger.Info("[5/6] Restarting Consul service...")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "consul"},
		Capture: true,
	})
	if err != nil {
		// Attempt to restore backup
		logger.Error("Failed to restart Consul", zap.String("output", output))
		if backupPath != "" {
			logger.Info("Attempting to restore backup", zap.String("backup", backupPath))
			if restoreErr := os.WriteFile(config.ConfigPath, existingConfig, 0640); restoreErr != nil {
				logger.Error("Failed to restore backup", zap.Error(restoreErr))
			}
		}
		return nil, fmt.Errorf("failed to restart Consul service: %s\n"+
			"Output: %s\n"+
			"Fix: Check 'sudo systemctl status consul' for details",
			err, output)
	}

	// Wait for Consul to start
	logger.Info("Waiting for Consul to start...")
	time.Sleep(3 * time.Second)

	// EVALUATE - Phase 6: Verify cluster membership
	logger.Info("[6/6] Verifying cluster membership...")
	var clusterMembers []string

	membersOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"members"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Failed to verify cluster membership (non-critical)", zap.Error(err))
	} else {
		logger.Debug("Cluster members output:\n" + membersOutput)
		clusterMembers = parseConsulMembers(membersOutput)
	}

	result := &NodeJoinResult{
		Success:        true,
		LocalNode:      localNode,
		JoinedNodes:    joinedNodes,
		BackupPath:     backupPath,
		ClusterMembers: clusterMembers,
	}

	logger.Info("Consul node join completed successfully",
		zap.String("local_node", localNode.Hostname),
		zap.Int("joined_count", len(joinedNodes)),
		zap.Int("cluster_size", len(clusterMembers)))

	return result, nil
}

// UpdateConsulConfig updates the Consul configuration with Tailscale settings
// This function is exported for testing purposes
func UpdateConsulConfig(existingConfig, bindAddr string, retryJoinAddrs []string) string {
	lines := strings.Split(existingConfig, "\n")
	var newLines []string
	inRetryJoinBlock := false
	foundBindAddr := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip existing retry_join lines
		if strings.HasPrefix(trimmed, "retry_join") {
			inRetryJoinBlock = true
			continue
		}
		if inRetryJoinBlock && (trimmed == "]" || trimmed == "") {
			inRetryJoinBlock = false
			continue
		}
		if inRetryJoinBlock {
			continue
		}

		// Update bind_addr
		if strings.HasPrefix(trimmed, "bind_addr") {
			newLines = append(newLines, fmt.Sprintf(`bind_addr = "%s"  # Tailscale IP`, bindAddr))
			foundBindAddr = true
			continue
		}

		newLines = append(newLines, line)
	}

	// Add bind_addr if not found
	if !foundBindAddr {
		newLines = append(newLines, "")
		newLines = append(newLines, fmt.Sprintf(`bind_addr = "%s"  # Tailscale IP`, bindAddr))
	}

	// Add retry_join configuration
	newLines = append(newLines, "")
	newLines = append(newLines, "# Cluster join configuration (Tailscale)")
	newLines = append(newLines, "retry_join = [")
	for _, addr := range retryJoinAddrs {
		newLines = append(newLines, fmt.Sprintf(`  "%s",  # Tailscale peer`, addr))
	}
	newLines = append(newLines, "]")

	return strings.Join(newLines, "\n")
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0640)
}

// parseConsulMembers parses 'consul members' output to extract member names
func parseConsulMembers(output string) []string {
	var members []string
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		// Skip header line
		if i == 0 {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// First column is member name
		fields := strings.Fields(trimmed)
		if len(fields) > 0 {
			members = append(members, fields[0])
		}
	}

	return members
}
