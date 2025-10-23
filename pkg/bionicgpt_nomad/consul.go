// pkg/bionicgpt_nomad/consul.go - Phase 5: Consul setup

package bionicgpt_nomad

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/cluster"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupConsul configures Consul for service discovery via WAN join
func (ei *EnterpriseInstaller) SetupConsul() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	logger.Info("Phase 5: Setting up Consul service discovery")

	// Check if already joined
	logger.Info("  [1/2] Checking current Consul cluster membership")
	if alreadyJoined, err := ei.checkConsulClusterMembership(); err != nil {
		return fmt.Errorf("failed to check Consul membership: %w", err)
	} else if alreadyJoined {
		logger.Info("    ✓ Already joined to Consul cluster")
		logger.Info("✓ Consul setup complete (already configured)")
		return nil
	}

	// Join cloud node via Tailscale
	logger.Info("  [2/2] Joining Consul cluster on cloud node")
	if err := ei.joinConsulCluster(); err != nil {
		return fmt.Errorf("failed to join Consul cluster: %w", err)
	}

	logger.Info("    ✓ Successfully joined Consul cluster")
	logger.Info("✓ Consul setup complete")
	return nil
}

// checkConsulClusterMembership checks if local Consul is already in a cluster with cloud node
func (ei *EnterpriseInstaller) checkConsulClusterMembership() (bool, error) {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Get cloud node Tailscale IP
	cloudIP, err := ei.getTailscaleIP(ei.config.CloudNode)
	if err != nil {
		return false, fmt.Errorf("failed to get cloud node Tailscale IP: %w", err)
	}

	// Discover current cluster members
	memberDiscovery, err := cluster.DiscoverMembers(ei.rc.Ctx, true)
	if err != nil {
		// If we can't discover members, assume not joined
		logger.Debug("Failed to discover cluster members (assuming not joined)", zap.Error(err))
		return false, nil
	}

	// Check if cloud IP is in cluster
	for _, member := range memberDiscovery.Members {
		if member.IP == cloudIP {
			logger.Debug("Cloud node found in cluster",
				zap.String("cloud_node", ei.config.CloudNode),
				zap.String("cloud_ip", cloudIP),
				zap.String("member_name", member.Name))
			return true, nil
		}
	}

	logger.Debug("Cloud node not found in cluster",
		zap.String("cloud_node", ei.config.CloudNode),
		zap.String("cloud_ip", cloudIP),
		zap.Int("current_members", len(memberDiscovery.Members)))

	return false, nil
}

// joinConsulCluster joins local Consul to cloud Consul via Tailscale WAN
func (ei *EnterpriseInstaller) joinConsulCluster() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Configure join operation
	joinConfig := consul.DefaultNodeJoinConfigV2()
	joinConfig.TargetNodes = []string{ei.config.CloudNode}
	joinConfig.DryRun = false
	joinConfig.SkipBackup = false
	joinConfig.PreserveNonTailscale = true
	joinConfig.AllowOffline = true // Cloud node might be temporarily offline

	logger.Info("    Joining Consul WAN with cloud node",
		zap.String("cloud_node", ei.config.CloudNode),
		zap.String("consul_address", ei.config.ConsulAddress))

	// Execute join operation
	result, err := consul.JoinNodesV2(ei.rc, joinConfig)
	if err != nil {
		return fmt.Errorf("failed to join Consul cluster: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("Consul join completed but reported failure")
	}

	logger.Info("    Consul WAN join successful",
		zap.String("local_node", result.LocalNode.Hostname),
		zap.String("local_ip", result.LocalNode.TailscaleIP),
		zap.Int("cluster_members", len(result.ClusterMembers)),
		zap.Bool("config_changed", result.ConfigChanged))

	return nil
}
