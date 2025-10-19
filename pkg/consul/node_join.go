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

	// ASSESS - Phase 2: Get existing cluster members (for idempotency)
	logger.Info("[2/8] Checking existing cluster configuration...")
	existingMembers, err := getExistingClusterMembers(rc)
	if err != nil {
		logger.Debug("No existing cluster members found (this might be first run)", zap.Error(err))
		existingMembers = make(map[string]string) // Empty map if no existing members
	}

	logger.Debug("Found existing cluster members",
		zap.Int("count", len(existingMembers)))

	// ASSESS - Phase 3: Resolve target nodes on Tailscale
	logger.Info("[3/8] Resolving target nodes on Tailscale...")
	var joinedNodes []NodeInfo
	targetNodeMap := make(map[string]string) // hostname -> IP

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
		targetNodeMap[peer.HostName] = targetIP

		logger.Info("Resolved target node",
			zap.String("node", nodeName),
			zap.String("hostname", peer.HostName),
			zap.String("tailscale_ip", targetIP),
			zap.Bool("online", peer.Online))
	}

	// ASSESS - Phase 4: Build complete retry_join list (merge existing + new)
	logger.Info("[4/8] Building complete cluster configuration...")
	retryJoinAddrs := buildCompleteRetryJoinList(existingMembers, targetNodeMap, myTailscaleIP)

	logger.Info("Complete retry_join list",
		zap.Strings("addresses", retryJoinAddrs),
		zap.Int("total_members", len(retryJoinAddrs)))

	// ASSESS - Phase 5: Backup existing Consul configuration
	var backupPath string
	if !config.SkipBackup && !config.DryRun {
		logger.Info("[5/8] Backing up Consul configuration...")
		backupPath = fmt.Sprintf("%s.backup.%d", config.ConfigPath, time.Now().Unix())

		if err := copyFile(config.ConfigPath, backupPath); err != nil {
			logger.Warn("Failed to backup configuration (non-critical)", zap.Error(err))
		} else {
			logger.Info("Configuration backed up", zap.String("backup", backupPath))
		}
	} else {
		logger.Info("[5/8] Skipping configuration backup")
	}

	// Return early if dry run
	if config.DryRun {
		logger.Info("[6/8] DRY RUN MODE - No changes will be made")
		logger.Info("Would configure Consul with:",
			zap.String("bind_addr", myTailscaleIP),
			zap.Strings("retry_join", retryJoinAddrs))

		return &NodeJoinResult{
			Success:     true,
			LocalNode:   localNode,
			JoinedNodes: joinedNodes,
		}, nil
	}

	// INTERVENE - Phase 6: Update Consul configuration
	logger.Info("[6/8] Updating Consul configuration...")

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

	// INTERVENE - Phase 7: Restart Consul service
	logger.Info("[7/8] Restarting Consul service...")
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

	// EVALUATE - Phase 8: Verify cluster membership
	logger.Info("[8/8] Verifying cluster membership...")
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

// getExistingClusterMembers gets current cluster members with their addresses
// Returns a map of hostname -> IP address
func getExistingClusterMembers(rc *eos_io.RuntimeContext) (map[string]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	members := make(map[string]string)

	// Get cluster members with detailed output
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"members", "-detailed"},
		Capture: true,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get cluster members: %w", err)
	}

	lines := strings.Split(output, "\n")
	for i, line := range lines {
		// Skip header line
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		// Parse: Node Address Status Type Build Protocol DC Partition Segment
		// Example: codemonkey-net-consul  100.122.172.67:8301  alive   server  1.18.0  2         dc1  default  <all>
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		nodeName := fields[0]
		address := fields[1]

		// Extract IP from "IP:PORT" format
		parts := strings.Split(address, ":")
		if len(parts) >= 1 {
			ip := parts[0]

			// Only include Tailscale IPs (100.x.x.x)
			if strings.HasPrefix(ip, "100.") {
				members[nodeName] = ip
				logger.Debug("Found existing cluster member",
					zap.String("node", nodeName),
					zap.String("ip", ip))
			}
		}
	}

	return members, nil
}

// buildCompleteRetryJoinList merges existing members with new targets
// Ensures all cluster members are in retry_join (idempotency)
// Excludes the local node's IP to prevent self-join
func buildCompleteRetryJoinList(existingMembers, targetNodes map[string]string, localIP string) []string {
	// Use a map to deduplicate IPs
	ipSet := make(map[string]bool)

	// Add existing member IPs (preserving cluster knowledge)
	for _, ip := range existingMembers {
		if ip != localIP { // Don't join to ourselves
			ipSet[ip] = true
		}
	}

	// Add new target IPs
	for _, ip := range targetNodes {
		if ip != localIP { // Don't join to ourselves
			ipSet[ip] = true
		}
	}

	// Convert set to sorted slice for consistency
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	// Sort for deterministic output
	sortIPs(ips)

	return ips
}

// sortIPs sorts IP addresses in a consistent way
func sortIPs(ips []string) {
	// Simple string sort works for our purposes
	// Could enhance with proper IP sorting if needed
	for i := 0; i < len(ips); i++ {
		for j := i + 1; j < len(ips); j++ {
			if ips[i] > ips[j] {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}
}
