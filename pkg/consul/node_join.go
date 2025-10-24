// pkg/consul/node_join_v2.go
// Enhanced business logic for joining Consul nodes over Tailscale network
// Complete rewrite with P0, P1, P2 fixes

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

// NodeInfo represents information about a Consul node
type NodeInfo struct {
	Hostname     string
	TailscaleIP  string
	DNSName      string
	Online       bool
	ConsulMember bool
}

// NodeJoinConfigV2 contains enhanced configuration for Consul node joining
type NodeJoinConfigV2 struct {
	TargetNodes          []string
	DryRun               bool
	SkipBackup           bool
	ConfigPath           string
	PreserveNonTailscale bool   // P0 fix: Preserve non-Tailscale IPs
	AllowOffline         bool   // P1 fix: Allow offline nodes in retry_join
	ACLToken             string // P1 fix: ACL support
	WaitTimeout          time.Duration
}

// NodeJoinResultV2 contains enhanced result information
type NodeJoinResultV2 struct {
	Success         bool
	LocalNode       NodeInfo
	JoinedNodes     []NodeInfo
	ExistingMembers []cluster.Member
	BackupPath      string
	ClusterMembers  []string
	ConfigChanged   bool     // P0 fix: Track if config actually changed
	MixedNetwork    bool     // P0 fix: Flag mixed Tailscale/non-Tailscale
	PreservedIPs    []string // P0 fix: Non-Tailscale IPs preserved
	ACLEnabled      bool     // P1 fix: ACL detection
}

// Default timeouts
const (
	DefaultWaitTimeout = 30 * time.Second
)

// DefaultNodeJoinConfigV2 returns enhanced config with sensible defaults
func DefaultNodeJoinConfigV2() *NodeJoinConfigV2 {
	return &NodeJoinConfigV2{
		ConfigPath:           "/etc/consul.d/consul.hcl",
		DryRun:               false,
		SkipBackup:           false,
		PreserveNonTailscale: true, // P0: Default to preserving mixed networks
		AllowOffline:         true, // P1: Allow offline nodes (retry_join purpose)
		WaitTimeout:          DefaultWaitTimeout,
	}
}

// JoinNodesV2 orchestrates joining Consul nodes with all P0-P3 fixes
// This is the main entry point for the enhanced sync operation
func JoinNodesV2(rc *eos_io.RuntimeContext, cfg *NodeJoinConfigV2) (*NodeJoinResultV2, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting enhanced Consul node join operation",
		zap.Strings("target_nodes", cfg.TargetNodes),
		zap.Bool("dry_run", cfg.DryRun),
		zap.Bool("preserve_non_tailscale", cfg.PreserveNonTailscale))

	result := &NodeJoinResultV2{
		Success: false,
	}

	// P2: Acquire lock to prevent concurrent operations
	if !cfg.DryRun {
		logger.Info("[1/12] Acquiring operation lock...")
		syncLock, err := lock.Acquire()
		if err != nil {
			return nil, err
		}
		defer func() { _ = syncLock.Release() }()
		logger.Debug("Lock acquired")
	} else {
		logger.Info("[1/12] Skipping lock (dry-run mode)")
	}

	// P1: Detect and setup ACL if enabled
	logger.Info("[2/12] Detecting ACL configuration...")
	aclEnabled, err := acl.DetectACLMode(rc.Ctx)
	if err != nil {
		logger.Warn("Could not detect ACL mode", zap.Error(err))
	}

	result.ACLEnabled = aclEnabled

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

	// Phase 1: Discover Tailscale network
	logger.Info("[3/12] Discovering Tailscale network...")
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

	// P1/P2: Discover existing cluster members (with better error handling)
	logger.Info("[4/12] Discovering existing cluster members...")
	memberDiscovery, err := cluster.DiscoverMembers(rc.Ctx, cfg.AllowOffline)
	if err != nil {
		// This is a critical error - we can't proceed safely
		return nil, fmt.Errorf("failed to discover existing cluster: %w\n"+
			"This is required for safe operation.\n"+
			"Ensure Consul is accessible or use --force to bypass (dangerous)", err)
	}

	result.ExistingMembers = memberDiscovery.Members
	result.MixedNetwork = memberDiscovery.HasMixedNetwork

	logger.Info("Existing cluster discovered",
		zap.Int("total_members", len(memberDiscovery.Members)),
		zap.Int("tailscale_members", len(memberDiscovery.TailscaleMembers)),
		zap.Int("non_tailscale_members", len(memberDiscovery.NonTailscaleMembers)),
		zap.Bool("mixed_network", result.MixedNetwork))

	// P0: Warn about mixed network topology
	if result.MixedNetwork {
		logger.Warn("MIXED NETWORK DETECTED",
			zap.String("action", "preserving non-Tailscale members in retry_join"))
		if cfg.PreserveNonTailscale {
			logger.Info("Non-Tailscale IPs will be preserved in configuration")
		} else {
			logger.Warn("Non-Tailscale IPs will be REMOVED (preserve_non_tailscale=false)")
		}
	}

	// Phase 3: Resolve target nodes on Tailscale
	logger.Info("[5/12] Resolving target nodes on Tailscale...")
	var joinedNodes []NodeInfo
	targetTailscaleIPs := make([]string, 0)

	for _, nodeName := range cfg.TargetNodes {
		peer, err := tsClient.FindPeerByHostname(nodeName)
		if err != nil {
			return nil, err
		}

		// P1: Allow offline nodes (that's what retry_join is for!)
		if !peer.Online && !cfg.AllowOffline {
			return nil, fmt.Errorf("node '%s' is offline\n"+
				"Retry_join requires nodes to be online for initial join.\n"+
				"Use --allow-offline to add offline nodes (they'll join when they come online)",
				nodeName)
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
		targetTailscaleIPs = append(targetTailscaleIPs, targetIP)

		logger.Info("Resolved target node",
			zap.String("node", nodeName),
			zap.String("hostname", peer.HostName),
			zap.String("tailscale_ip", targetIP),
			zap.Bool("online", peer.Online))
	}

	result.JoinedNodes = joinedNodes

	// Phase 4: Build complete retry_join list
	logger.Info("[6/12] Building complete retry_join configuration...")

	// Get existing Tailscale IPs from cluster
	existingTailscaleIPs := memberDiscovery.GetTailscaleIPs()

	// Merge: existing Tailscale + new targets (deduplicated)
	allTailscaleIPs := mergeAndDeduplicateIPs(existingTailscaleIPs, targetTailscaleIPs, myTailscaleIP)

	logger.Info("Complete Tailscale retry_join list",
		zap.Strings("ips", allTailscaleIPs),
		zap.Int("count", len(allTailscaleIPs)))

	// P0: Prepare non-Tailscale IPs for preservation if requested
	var preservedIPs []string
	if cfg.PreserveNonTailscale && len(memberDiscovery.NonTailscaleMembers) > 0 {
		for _, member := range memberDiscovery.NonTailscaleMembers {
			preservedIPs = append(preservedIPs, member.IP)
		}
		result.PreservedIPs = preservedIPs

		logger.Info("Preserving non-Tailscale IPs",
			zap.Strings("ips", preservedIPs),
			zap.Int("count", len(preservedIPs)))
	}

	// Phase 5: Read and parse existing configuration
	logger.Info("[7/12] Reading existing Consul configuration...")
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

	// P0: Check if configuration actually needs updating (TRUE IDEMPOTENCY)
	logger.Info("[8/12] Checking if configuration needs updating...")
	needsUpdate := config.NeedsUpdate(existingConfig, myTailscaleIP, allTailscaleIPs)

	result.ConfigChanged = needsUpdate

	if !needsUpdate {
		logger.Info("Configuration is already correct - checking cluster membership...")
		logger.Info("Current bind_addr: " + existingConfig.BindAddr)
		logger.Info("Current retry_join: " + fmt.Sprintf("%v", existingConfig.RetryJoin))
		logger.Info("Desired bind_addr: " + myTailscaleIP)
		logger.Info("Desired retry_join: " + fmt.Sprintf("%v", allTailscaleIPs))

		// P0 FIX: Even if config is correct, verify cluster is actually joined
		// Config might be right but Consul might not have connected yet (network issues, remote nodes down, etc.)
		currentMemberCount := len(memberDiscovery.Members)
		expectedMemberCount := len(allTailscaleIPs) + 1 // +1 for self

		if currentMemberCount >= expectedMemberCount {
			// Cluster is actually joined - truly idempotent
			logger.Info("Cluster membership verified - all nodes connected")
			result.Success = true
			result.ClusterMembers = parseConsulMembersSimple(memberDiscovery)
			return result, nil
		}

		// Config is correct BUT cluster not fully joined - need to trigger join
		logger.Warn("Configuration correct but cluster not fully joined",
			zap.Int("current_members", currentMemberCount),
			zap.Int("expected_members", expectedMemberCount))
		logger.Info("Will restart Consul to trigger cluster join...")

		// Continue to restart Consul to trigger join (without updating config)
		result.ConfigChanged = false // Config stays the same
		// Fall through to restart logic below
	} else {
		logger.Info("Configuration needs updating",
			zap.String("current_bind", existingConfig.BindAddr),
			zap.String("desired_bind", myTailscaleIP),
			zap.Int("current_retry_join_count", len(existingConfig.RetryJoin)),
			zap.Int("desired_retry_join_count", len(allTailscaleIPs)))
	}

	// Dry-run: Show what would change
	if cfg.DryRun {
		logger.Info("[9/12] DRY RUN - Configuration changes that would be made:")
		logger.Info("")
		logger.Info("Current Configuration:")
		logger.Info("  bind_addr:   " + existingConfig.BindAddr)
		logger.Info("  retry_join:  " + fmt.Sprintf("%v", existingConfig.RetryJoin))
		logger.Info("")
		logger.Info("New Configuration:")
		logger.Info("  bind_addr:   " + myTailscaleIP)
		logger.Info("  retry_join:  " + fmt.Sprintf("%v", allTailscaleIPs))
		if len(preservedIPs) > 0 {
			logger.Info("  preserved:   " + fmt.Sprintf("%v", preservedIPs))
		}
		logger.Info("")
		logger.Info("Actions that would be taken:")
		logger.Info("  1. Backup config to: " + cfg.ConfigPath + ".backup.<timestamp>")
		logger.Info("  2. Update configuration atomically")
		logger.Info("  3. Validate new configuration")
		logger.Info("  4. Restart Consul service")
		logger.Info("  5. Wait for Consul to become ready")
		logger.Info("  6. Verify cluster membership")

		result.Success = true
		return result, nil
	}

	// Phase 6: Backup configuration (only if config will change)
	var backupPath string
	if needsUpdate {
		if !cfg.SkipBackup {
			logger.Info("[9/12] Backing up Consul configuration...")
			backupPath = fmt.Sprintf("%s.backup.%d", cfg.ConfigPath, time.Now().Unix())

			if err := copyFile(cfg.ConfigPath, backupPath); err != nil {
				logger.Warn("Failed to backup configuration (non-critical)", zap.Error(err))
			} else {
				logger.Info("Configuration backed up", zap.String("backup", backupPath))
				result.BackupPath = backupPath
			}
		} else {
			logger.Info("[9/12] Skipping configuration backup")
		}

		// Phase 7: Generate new configuration
		logger.Info("[10/12] Generating new configuration...")
		newConfigContent := config.UpdateConfig(
			string(existingConfigData),
			myTailscaleIP,
			allTailscaleIPs,
			cfg.PreserveNonTailscale,
		)

		// P0: Write configuration atomically
		logger.Debug("Writing configuration atomically")
		if err := service.WriteConfigAtomic(cfg.ConfigPath, []byte(newConfigContent)); err != nil {
			return nil, fmt.Errorf("failed to write configuration: %w", err)
		}

		// P0: Validate configuration before applying
		logger.Debug("Validating new configuration")
		if err := service.ValidateConfig(rc.Ctx, cfg.ConfigPath); err != nil {
			// Validation failed - restore backup
			if backupPath != "" {
				logger.Error("Configuration validation failed, restoring backup")
				_ = os.WriteFile(cfg.ConfigPath, existingConfigData, ConsulConfigPerm)
			}
			return nil, err
		}

		logger.Info("Configuration updated successfully")
	} else {
		logger.Info("[9/12] Skipping config backup (config already correct)")
		logger.Info("[10/12] Skipping config update (config already correct)")
	}

	// Phase 8: Restart Consul with rollback support
	logger.Info("[11/12] Restarting Consul service...")
	if err := service.RestartWithRollback(rc.Ctx, cfg.ConfigPath, existingConfigData); err != nil {
		return nil, err
	}

	// P1: Wait for Consul to be ready (not just sleep!)
	if err := service.WaitForReady(rc.Ctx, cfg.WaitTimeout); err != nil {
		logger.Error("Consul failed to become ready after restart")
		return nil, err
	}

	// Phase 9: Verify cluster membership
	logger.Info("[12/12] Verifying cluster membership...")
	finalMembers, err := cluster.DiscoverMembers(rc.Ctx, true)
	if err != nil {
		logger.Warn("Failed to verify final cluster state", zap.Error(err))
	} else {
		result.ClusterMembers = parseConsulMembersSimple(finalMembers)
		logger.Info("Cluster membership verified",
			zap.Int("member_count", len(finalMembers.Members)))
	}

	result.Success = true

	logger.Info("Consul node join completed successfully",
		zap.String("local_node", result.LocalNode.Hostname),
		zap.Int("joined_count", len(result.JoinedNodes)),
		zap.Int("cluster_size", len(result.ClusterMembers)),
		zap.Bool("config_changed", result.ConfigChanged))

	return result, nil
}

// Helper functions

func mergeAndDeduplicateIPs(existing, new []string, excludeIP string) []string {
	ipSet := make(map[string]bool)

	// Add existing IPs
	for _, ip := range existing {
		if ip != excludeIP {
			ipSet[ip] = true
		}
	}

	// Add new IPs
	for _, ip := range new {
		if ip != excludeIP {
			ipSet[ip] = true
		}
	}

	// Convert to sorted slice
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	sortIPs(ips)
	return ips
}

func parseConsulMembersSimple(discovery *cluster.MemberDiscoveryResult) []string {
	var members []string
	for _, member := range discovery.Members {
		members = append(members, member.Name)
	}
	return members
}

func sortIPs(ips []string) {
	for i := 0; i < len(ips); i++ {
		for j := i + 1; j < len(ips); j++ {
			if ips[i] > ips[j] {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, ConsulConfigPerm)
}
