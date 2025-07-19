// cmd/create/bootstrap_enhanced.go

package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Bootstrap flags for cluster management
var (
	joinCluster   string
	singleNode    bool
	preferredRole string
	autoDiscover  bool
)

func init() {
	// Add flags to existing bootstrap commands
	bootstrapCmd.Flags().StringVar(&joinCluster, "join-cluster", "", 
		"Join existing cluster at specified master address")
	bootstrapCmd.Flags().BoolVar(&singleNode, "single-node", false,
		"Explicitly configure as single-node deployment")
	bootstrapCmd.Flags().StringVar(&preferredRole, "preferred-role", "",
		"Preferred role when joining cluster (edge/core/data/compute)")
	bootstrapCmd.Flags().BoolVar(&autoDiscover, "auto-discover", false,
		"Enable automatic cluster discovery via multicast")
		
	// Also add to the all command
	bootstrapAllCmd.Flags().StringVar(&joinCluster, "join-cluster", "", 
		"Join existing cluster at specified master address")
	bootstrapAllCmd.Flags().BoolVar(&singleNode, "single-node", false,
		"Explicitly configure as single-node deployment")
	bootstrapAllCmd.Flags().StringVar(&preferredRole, "preferred-role", "",
		"Preferred role when joining cluster (edge/core/data/compute)")
	bootstrapAllCmd.Flags().BoolVar(&autoDiscover, "auto-discover", false,
		"Enable automatic cluster discovery via multicast")
}

// runBootstrapAllEnhanced is the enhanced version with cluster support
func runBootstrapAllEnhanced(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting enhanced infrastructure bootstrap")
	
	// ASSESS - Detect cluster state
	clusterInfo, err := bootstrap.DetectClusterState(rc, bootstrap.Options{
		JoinCluster:   joinCluster,
		SingleNode:    singleNode,
		PreferredRole: preferredRole,
		AutoDiscover:  autoDiscover,
	})
	if err != nil {
		return fmt.Errorf("failed to detect cluster state: %w", err)
	}
	
	// Log cluster information
	logger.Info("Cluster state detected",
		zap.Bool("single_node", clusterInfo.IsSingleNode),
		zap.Bool("is_master", clusterInfo.IsMaster),
		zap.String("master_addr", clusterInfo.MasterAddr),
		zap.Int("node_count", clusterInfo.NodeCount),
		zap.String("my_role", string(clusterInfo.MyRole)))
	
	// INTERVENE - Bootstrap based on node type
	if clusterInfo.IsSingleNode || clusterInfo.IsMaster {
		// Single node or first master
		logger.Info("Bootstrapping as single node or first master")
		return bootstrapSingleNodeEnhanced(rc, clusterInfo)
	} else {
		// Joining existing cluster
		logger.Info("Bootstrapping as additional node",
			zap.String("master", clusterInfo.MasterAddr))
		return bootstrapAdditionalNode(rc, clusterInfo)
	}
}

// bootstrapSingleNodeEnhanced bootstraps a single node with storage ops
func bootstrapSingleNodeEnhanced(rc *eos_io.RuntimeContext, clusterInfo *bootstrap.ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Phase 1: Install Salt
	logger.Info("Phase 1: Bootstrapping Salt", zap.Int("phase", 1), zap.Int("total_phases", 6))
	saltConfig := &saltstack.Config{
		MasterMode: !clusterInfo.IsSingleNode, // Master mode for multi-node
		LogLevel:   "warning",
	}
	if err := saltstack.Install(rc, saltConfig); err != nil {
		return fmt.Errorf("salt bootstrap failed: %w", err)
	}
	
	// Phase 1.5: Setup Salt API (for master nodes)
	if clusterInfo.IsMaster || clusterInfo.IsSingleNode {
		logger.Info("Phase 1.5: Setting up Salt API", zap.Int("phase", 1), zap.Int("total_phases", 6))
		if err := bootstrap.SetupSaltAPI(rc); err != nil {
			logger.Warn("Salt API setup failed, continuing without API", zap.Error(err))
			// Continue anyway - the system can work without the API
		}
	}
	
	// Phase 2: Deploy Storage Operations
	logger.Info("Phase 2: Deploying Storage Operations", zap.Int("phase", 2), zap.Int("total_phases", 6))
	if err := bootstrap.DeployStorageOps(rc, clusterInfo); err != nil {
		return fmt.Errorf("storage ops deployment failed: %w", err)
	}
	
	// Phase 3: Bootstrap Vault
	logger.Info("Phase 3: Bootstrapping Vault", zap.Int("phase", 3), zap.Int("total_phases", 6))
	if err := vault.OrchestrateVaultCreateViaSalt(rc); err != nil {
		return fmt.Errorf("vault bootstrap failed: %w", err)
	}
	
	// Phase 4: Bootstrap Nomad
	logger.Info("Phase 4: Bootstrapping Nomad", zap.Int("phase", 4), zap.Int("total_phases", 6))
	if err := nomad.DeployNomadViaSaltBootstrap(rc); err != nil {
		return fmt.Errorf("nomad bootstrap failed: %w", err)
	}
	
	// Phase 5: Bootstrap OSQuery
	logger.Info("Phase 5: Bootstrapping OSQuery", zap.Int("phase", 5), zap.Int("total_phases", 6))
	if err := osquery.InstallOsquery(rc); err != nil {
		return fmt.Errorf("osquery bootstrap failed: %w", err)
	}
	
	// Save cluster configuration for future reference
	if err := bootstrap.SaveClusterConfig(rc, clusterInfo); err != nil {
		logger.Warn("Failed to save cluster config", zap.Error(err))
	}
	
	// Start storage monitoring
	logger.Info("Starting storage monitoring service")
	// The service was already created and enabled, just start it
	
	logger.Info("Single node bootstrap completed successfully")
	showPostBootstrapInfo(logger, clusterInfo)
	
	return nil
}

// bootstrapAdditionalNode bootstraps a node joining an existing cluster
func bootstrapAdditionalNode(rc *eos_io.RuntimeContext, clusterInfo *bootstrap.ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Phase 0: Health checks
	logger.Info("Phase 0: Running pre-join health checks")
	healthResult, err := bootstrap.PerformHealthChecks(rc, clusterInfo.MasterAddr)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	
	if !healthResult.Passed {
		logger.Error("Health checks failed",
			zap.Strings("failed_checks", healthResult.FailedChecks))
		return fmt.Errorf("pre-join health checks failed: %v", healthResult.FailedChecks)
	}
	
	if len(healthResult.Warnings) > 0 {
		logger.Warn("Health check warnings",
			zap.Strings("warnings", healthResult.Warnings))
	}
	
	// Create node registration
	reg := bootstrap.NodeRegistration{
		PreferredRole: preferredRole,
	}
	
	// Phase 1: Register with master
	logger.Info("Phase 1: Registering with cluster master", 
		zap.String("master", clusterInfo.MasterAddr))
	
	result, err := bootstrap.RegisterNode(rc, clusterInfo.MasterAddr, reg)
	if err != nil {
		return fmt.Errorf("node registration failed: %w", err)
	}
	
	if !result.Accepted {
		return fmt.Errorf("node registration was not accepted by master")
	}
	
	logger.Info("Node registered successfully",
		zap.String("assigned_role", string(result.AssignedRole)),
		zap.String("cluster_id", result.ClusterID))
	
	// Update cluster info with registration result
	clusterInfo.MyRole = result.AssignedRole
	clusterInfo.ClusterID = result.ClusterID
	
	// Phase 2: Deploy storage operations with assigned role
	logger.Info("Phase 2: Deploying Storage Operations for assigned role",
		zap.String("role", string(result.AssignedRole)))
	
	if err := bootstrap.DeployStorageOps(rc, clusterInfo); err != nil {
		return fmt.Errorf("storage ops deployment failed: %w", err)
	}
	
	// Phase 3: Apply Salt highstate to configure node
	logger.Info("Phase 3: Applying Salt highstate for node configuration")
	// The master will push the appropriate states based on our role
	
	// Save cluster configuration
	if err := bootstrap.SaveClusterConfig(rc, clusterInfo); err != nil {
		logger.Warn("Failed to save cluster config", zap.Error(err))
	}
	
	logger.Info("Additional node bootstrap completed successfully")
	showPostBootstrapInfo(logger, clusterInfo)
	
	return nil
}

// showPostBootstrapInfo displays helpful information after bootstrap
func showPostBootstrapInfo(logger otelzap.LoggerWithCtx, info *bootstrap.ClusterInfo) {
	logger.Info("=== Bootstrap Complete ===")
	logger.Info("Node Information",
		zap.String("role", string(info.MyRole)),
		zap.Int("cluster_size", info.NodeCount))
	
	if info.IsSingleNode {
		logger.Info("Single-node deployment ready")
		logger.Info("Next steps:")
		logger.Info("1. Check storage status: eos read storage-analyze")
		logger.Info("2. Monitor storage: eos read storage-monitor")
		logger.Info("3. View Vault status: eos read vault status")
	} else {
		logger.Info("Multi-node deployment configured")
		logger.Info("Cluster ID: " + info.ClusterID)
		if info.IsMaster {
			logger.Info("This node is the cluster master")
			logger.Info("To add more nodes, run on new machines:")
			logger.Info("  eos bootstrap --join-cluster=" + getNodeIP())
		} else {
			logger.Info("This node has joined the cluster")
			logger.Info("Master: " + info.MasterAddr)
		}
	}
	
	logger.Info("Storage monitoring will start automatically")
	logger.Info("Configuration: /etc/eos/storage-ops.yaml")
}

// getNodeIP gets the primary IP (helper function)
func getNodeIP() string {
	// This is simplified, in production would be more robust
	return "YOUR_MASTER_IP"
}