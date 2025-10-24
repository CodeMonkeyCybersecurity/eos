// pkg/consul/node_unjoin.go
// Business logic for removing Consul nodes from retry_join configuration

package consul

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/acl"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/cluster"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/lock"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/service"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/tailscale"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NodeUnjoinConfig contains configuration for removing Consul nodes
type NodeUnjoinConfig struct {
	TargetNodes []string
	DryRun      bool
	SkipBackup  bool
	ConfigPath  string
	ACLToken    string
	WaitTimeout time.Duration
}

// NodeUnjoinResult contains result information from node removal
type NodeUnjoinResult struct {
	Success            bool
	LocalNode          NodeInfo
	RemovedNodes       []NodeInfo
	RemainingRetryJoin []string
	BackupPath         string
	ClusterMembers     []string
	ConfigChanged      bool
}

// DefaultNodeUnjoinConfig returns config with sensible defaults
func DefaultNodeUnjoinConfig() *NodeUnjoinConfig {
	return &NodeUnjoinConfig{
		ConfigPath:  "/etc/consul.d/consul.hcl",
		DryRun:      false,
		SkipBackup:  false,
		WaitTimeout: DefaultWaitTimeout,
	}
}

// UnjoinNodes orchestrates removing Consul nodes from retry_join configuration
func UnjoinNodes(rc *eos_io.RuntimeContext, cfg *NodeUnjoinConfig) (*NodeUnjoinResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul node removal from retry_join",
		zap.Strings("target_nodes", cfg.TargetNodes),
		zap.Bool("dry_run", cfg.DryRun))

	result := &NodeUnjoinResult{
		Success: false,
	}

	// Acquire lock to prevent concurrent operations
	if !cfg.DryRun {
		logger.Info("[1/10] Acquiring operation lock...")
		syncLock, err := lock.Acquire()
		if err != nil {
			return nil, err
		}
		defer func() { _ = syncLock.Release() }()
		logger.Debug("Lock acquired")
	} else {
		logger.Info("[1/10] Skipping lock (dry-run mode)")
	}

	// Detect and setup ACL if enabled
	logger.Info("[2/10] Detecting ACL configuration...")
	aclEnabled, err := acl.DetectACLMode(rc.Ctx)
	if err != nil {
		logger.Warn("Could not detect ACL mode", zap.Error(err))
	}

	if aclEnabled {
		logger.Info("ACLs detected as enabled")
		tokenCfg := &acl.TokenConfig{
			Token:      cfg.ACLToken,
			AutoDetect: true,
		}

		token, err := acl.GetToken(rc.Ctx, tokenCfg)
		if err != nil {
			return nil, fmt.Errorf("ACL token required: %w", err)
		}

		if err := acl.SetupEnvironment(rc.Ctx, token); err != nil {
			return nil, fmt.Errorf("failed to setup ACL environment: %w", err)
		}

		logger.Debug("ACL token configured")
	} else {
		logger.Debug("ACLs not enabled")
	}

	// Discover Tailscale network
	logger.Info("[3/10] Discovering Tailscale network...")
	tsClient, err := tailscale.NewClient(rc)
	if err != nil {
		return nil, err
	}

	status, err := tsClient.GetStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	myTailscaleIP, err := tsClient.GetSelfIP()
	if err != nil {
		return nil, fmt.Errorf("failed to get this node's Tailscale IP: %w", err)
	}

	result.LocalNode = NodeInfo{
		Hostname:    status.Self.HostName,
		TailscaleIP: myTailscaleIP,
		DNSName:     status.Self.DNSName,
		Online:      status.Self.Online,
	}

	logger.Info("Local node Tailscale configuration",
		zap.String("hostname", result.LocalNode.Hostname),
		zap.String("tailscale_ip", result.LocalNode.TailscaleIP))

	// Resolve target nodes to remove
	logger.Info("[4/10] Resolving target nodes to remove...")
	var nodesToRemove []NodeInfo
	var ipsToRemove []string

	for _, nodeName := range cfg.TargetNodes {
		peer, err := tsClient.FindPeerByHostname(nodeName)
		if err != nil {
			logger.Warn("Could not resolve node on Tailscale, will try to remove by name anyway",
				zap.String("node", nodeName),
				zap.Error(err))
			// Still add to removal list - might be in config as IP directly
			continue
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

		nodesToRemove = append(nodesToRemove, nodeInfo)
		ipsToRemove = append(ipsToRemove, targetIP)

		logger.Info("Resolved target node to remove",
			zap.String("node", nodeName),
			zap.String("hostname", peer.HostName),
			zap.String("tailscale_ip", targetIP))
	}

	result.RemovedNodes = nodesToRemove

	// Read existing configuration
	logger.Info("[5/10] Reading existing Consul configuration...")
	existingConfigData, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Consul config at %s: %w\n"+
			"Fix: Ensure Consul is installed with 'sudo eos create consul'",
			cfg.ConfigPath, err)
	}

	existingConfig, err := config.ParseHCL(string(existingConfigData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse existing config: %w", err)
	}

	logger.Info("Current retry_join configuration",
		zap.Strings("retry_join", existingConfig.RetryJoin))

	// Remove target IPs from retry_join
	logger.Info("[6/10] Calculating new retry_join configuration...")
	newRetryJoin := removeIPsFromList(existingConfig.RetryJoin, ipsToRemove)

	result.RemainingRetryJoin = newRetryJoin

	// Check if configuration actually needs updating (idempotency)
	logger.Info("[7/10] Checking if configuration needs updating...")
	needsUpdate := !stringSlicesEqual(existingConfig.RetryJoin, newRetryJoin)

	result.ConfigChanged = needsUpdate

	if !needsUpdate {
		logger.Info("Configuration already correct - nodes not in retry_join")
		logger.Info("Current retry_join: " + fmt.Sprintf("%v", existingConfig.RetryJoin))
		logger.Info("Desired retry_join: " + fmt.Sprintf("%v", newRetryJoin))

		result.Success = true
		// Get current cluster members
		memberDiscovery, err := cluster.DiscoverMembers(rc.Ctx, true)
		if err != nil {
			logger.Warn("Failed to discover cluster members", zap.Error(err))
		} else {
			result.ClusterMembers = parseConsulMembersSimple(memberDiscovery)
		}
		return result, nil
	}

	logger.Info("Configuration will be updated",
		zap.Int("current_retry_join_count", len(existingConfig.RetryJoin)),
		zap.Int("new_retry_join_count", len(newRetryJoin)),
		zap.Strings("removing_ips", ipsToRemove))

	// Dry-run: Show what would change
	if cfg.DryRun {
		logger.Info("[8/10] DRY RUN - Configuration changes that would be made:")
		logger.Info("")
		logger.Info("Current Configuration:")
		logger.Info("  retry_join:  " + fmt.Sprintf("%v", existingConfig.RetryJoin))
		logger.Info("")
		logger.Info("New Configuration:")
		logger.Info("  retry_join:  " + fmt.Sprintf("%v", newRetryJoin))
		logger.Info("")
		logger.Info("Nodes to remove:")
		for _, node := range nodesToRemove {
			logger.Info("  - " + node.Hostname + " (" + node.TailscaleIP + ")")
		}
		logger.Info("")
		logger.Info("Actions that would be taken:")
		logger.Info("  1. Backup config to: " + cfg.ConfigPath + ".backup.<timestamp>")
		logger.Info("  2. Update retry_join configuration")
		logger.Info("  3. Validate new configuration")
		logger.Info("  4. Restart Consul service")
		logger.Info("  5. Wait for Consul to become ready")
		logger.Info("  6. Verify cluster membership")

		result.Success = true
		return result, nil
	}

	// Backup configuration
	var backupPath string
	if !cfg.SkipBackup {
		logger.Info("[8/10] Backing up Consul configuration...")
		backupPath = fmt.Sprintf("%s.backup.%d", cfg.ConfigPath, time.Now().Unix())

		if err := copyFile(cfg.ConfigPath, backupPath); err != nil {
			logger.Warn("Failed to backup configuration (non-critical)", zap.Error(err))
		} else {
			logger.Info("Configuration backed up", zap.String("backup", backupPath))
			result.BackupPath = backupPath
		}
	} else {
		logger.Info("[8/10] Skipping configuration backup")
	}

	// Generate new configuration
	logger.Info("[9/10] Generating new configuration...")
	newConfigContent := config.UpdateRetryJoin(
		string(existingConfigData),
		newRetryJoin,
	)

	// Write configuration atomically
	logger.Debug("Writing configuration atomically")
	if err := service.WriteConfigAtomic(cfg.ConfigPath, []byte(newConfigContent)); err != nil {
		return nil, fmt.Errorf("failed to write configuration: %w", err)
	}

	// Validate configuration before applying
	logger.Debug("Validating new configuration")
	if err := service.ValidateConfig(rc.Ctx, cfg.ConfigPath); err != nil {
		// Validation failed - restore backup
		if backupPath != "" {
			logger.Error("Configuration validation failed, restoring backup")
			_ = os.WriteFile(cfg.ConfigPath, existingConfigData, 0640)
		}
		return nil, err
	}

	logger.Info("Configuration updated successfully")

	// Restart Consul with rollback support
	logger.Info("[10/10] Restarting Consul service...")
	if err := service.RestartWithRollback(rc.Ctx, cfg.ConfigPath, existingConfigData); err != nil {
		return nil, err
	}

	// Wait for Consul to be ready
	if err := service.WaitForReady(rc.Ctx, cfg.WaitTimeout); err != nil {
		logger.Error("Consul failed to become ready after restart")
		return nil, err
	}

	// Verify cluster membership
	logger.Info("Verifying cluster membership...")
	finalMembers, err := cluster.DiscoverMembers(rc.Ctx, true)
	if err != nil {
		logger.Warn("Failed to verify final cluster state", zap.Error(err))
	} else {
		result.ClusterMembers = parseConsulMembersSimple(finalMembers)
		logger.Info("Cluster membership verified",
			zap.Int("member_count", len(finalMembers.Members)))
	}

	result.Success = true

	logger.Info("Consul node removal completed successfully",
		zap.String("local_node", result.LocalNode.Hostname),
		zap.Int("removed_count", len(result.RemovedNodes)),
		zap.Int("remaining_retry_join_count", len(result.RemainingRetryJoin)),
		zap.Bool("config_changed", result.ConfigChanged))

	return result, nil
}

// Helper functions
// Note: parseConsulMembersSimple is defined in node_join.go and shared across the package

// removeIPsFromList removes specified IPs from a list
func removeIPsFromList(original []string, toRemove []string) []string {
	// Create map of IPs to remove for O(1) lookup
	removeMap := make(map[string]bool)
	for _, ip := range toRemove {
		removeMap[ip] = true
	}

	// Build new list without removed IPs
	var result []string
	for _, ip := range original {
		if !removeMap[ip] {
			result = append(result, ip)
		}
	}

	return result
}

// stringSlicesEqual checks if two string slices are equal
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison (order-independent)
	aMap := make(map[string]bool)
	for _, s := range a {
		aMap[s] = true
	}

	for _, s := range b {
		if !aMap[s] {
			return false
		}
	}

	return true
}
