// Package connectors provides service connector implementations
package connectors

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

// ConsulTailscaleConnector implements Consul multi-node clustering over Tailscale
type ConsulTailscaleConnector struct {
	targetNodes []string
	tsClient    *tailscale.Client
}

// ConsulTailscaleSyncConfig contains configuration for Consul-Tailscale sync
type ConsulTailscaleSyncConfig struct {
	TargetNodes []string
	DryRun      bool
	Force       bool
	SkipBackup  bool
}

// NewConsulTailscaleConnector creates a new Consul-Tailscale connector
func NewConsulTailscaleConnector(rc *eos_io.RuntimeContext, targetNodes []string) (*ConsulTailscaleConnector, error) {
	// Create Tailscale client
	tsClient, err := tailscale.NewClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tailscale client: %w", err)
	}

	return &ConsulTailscaleConnector{
		targetNodes: targetNodes,
		tsClient:    tsClient,
	}, nil
}

// Sync performs the Consul-Tailscale integration
func (c *ConsulTailscaleConnector) Sync(rc *eos_io.RuntimeContext, config *ConsulTailscaleSyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul-Tailscale cluster synchronization",
		zap.Strings("target_nodes", config.TargetNodes),
		zap.Bool("dry_run", config.DryRun))

	// Phase 1: Get this node's Tailscale IP
	logger.Info("[1/6] Discovering Tailscale network...")
	myTailscaleIP, err := c.tsClient.GetSelfIP()
	if err != nil {
		return fmt.Errorf("failed to get this node's Tailscale IP: %w", err)
	}

	status, err := c.tsClient.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	logger.Info("This node's Tailscale configuration",
		zap.String("hostname", status.Self.HostName),
		zap.String("tailscale_ip", myTailscaleIP))

	// Phase 2: Resolve target nodes
	logger.Info("[2/6] Resolving target nodes on Tailscale...")
	var retryJoinAddrs []string

	for _, nodeName := range config.TargetNodes {
		peer, err := c.tsClient.FindPeerByHostname(nodeName)
		if err != nil {
			return err // Already has user-friendly error message
		}

		// Verify peer is online
		if err := c.tsClient.VerifyPeerOnline(peer); err != nil {
			return err // Already has user-friendly error message
		}

		targetIP, err := c.tsClient.GetPeerIP(peer)
		if err != nil {
			return fmt.Errorf("failed to get IP for node '%s': %w", nodeName, err)
		}

		retryJoinAddrs = append(retryJoinAddrs, targetIP)

		logger.Info("Resolved target node",
			zap.String("node", nodeName),
			zap.String("hostname", peer.HostName),
			zap.String("tailscale_ip", targetIP),
			zap.Bool("online", peer.Online))
	}

	// Phase 3: Backup existing Consul configuration
	if !config.SkipBackup && !config.DryRun {
		logger.Info("[3/6] Backing up Consul configuration...")
		consulConfigPath := "/etc/consul.d/consul.hcl"
		backupPath := fmt.Sprintf("%s.backup.%d", consulConfigPath, time.Now().Unix())

		if err := c.copyFile(consulConfigPath, backupPath); err != nil {
			logger.Warn("Failed to backup configuration", zap.Error(err))
		} else {
			logger.Info("Configuration backed up", zap.String("backup", backupPath))
		}
	} else {
		logger.Info("[3/6] Skipping configuration backup")
	}

	// Phase 4: Update Consul configuration
	logger.Info("[4/6] Updating Consul configuration...")

	if config.DryRun {
		logger.Info("DRY RUN: Would configure Consul with:",
			zap.String("bind_addr", myTailscaleIP),
			zap.Strings("retry_join", retryJoinAddrs))
		return nil
	}

	// Read existing config
	consulConfigPath := "/etc/consul.d/consul.hcl"
	existingConfig, err := os.ReadFile(consulConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read Consul config: %w", err)
	}

	// Update configuration
	newConfig := updateConsulConfig(string(existingConfig), myTailscaleIP, retryJoinAddrs)

	// Write new configuration
	if err := os.WriteFile(consulConfigPath, []byte(newConfig), 0640); err != nil {
		return fmt.Errorf("failed to write Consul config: %w", err)
	}

	logger.Info("Consul configuration updated",
		zap.String("config", consulConfigPath))

	// Phase 5: Restart Consul
	logger.Info("[5/6] Restarting Consul service...")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "consul"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart Consul: %s\nOutput: %s", err, output)
	}

	// Wait for Consul to start
	logger.Info("Waiting for Consul to start...")
	time.Sleep(3 * time.Second)

	// Phase 6: Verify cluster membership
	logger.Info("[6/6] Verifying cluster membership...")
	membersOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"members"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Failed to verify cluster membership", zap.Error(err))
	} else {
		logger.Info("Cluster members:\n" + membersOutput)
	}

	logger.Info("Consul-Tailscale synchronization completed successfully",
		zap.String("bind_addr", myTailscaleIP),
		zap.Strings("joined_nodes", config.TargetNodes))

	return nil
}

// updateConsulConfig updates the Consul configuration with Tailscale settings
func updateConsulConfig(existingConfig, bindAddr string, retryJoinAddrs []string) string {
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
func (c *ConsulTailscaleConnector) copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0640)
}
