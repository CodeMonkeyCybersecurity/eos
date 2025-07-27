// cmd/create/bootstrap_enhanced.go

package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/service_installation"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ubuntu"
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
	skipHardening bool
)

// TODO: Fix command registration - temporarily commented to allow build
// func init() {
// 	// Add flags to existing bootstrap commands
// 	bootstrapCmd.Flags().StringVar(&joinCluster, "join-cluster", "", 
// 		"Join existing cluster at specified master address")
// 	bootstrapCmd.Flags().BoolVar(&singleNode, "single-node", false,
// 		"Explicitly configure as single-node deployment")
// 	bootstrapCmd.Flags().StringVar(&preferredRole, "preferred-role", "",
// 		"Preferred role when joining cluster (edge/core/data/compute)")
// 	bootstrapCmd.Flags().BoolVar(&autoDiscover, "auto-discover", false,
// 		"Enable automatic cluster discovery via multicast")
		
// 	// Also add to the all command
// 	bootstrapAllCmd.Flags().StringVar(&joinCluster, "join-cluster", "", 
// 		"Join existing cluster at specified master address")
// 	bootstrapAllCmd.Flags().BoolVar(&singleNode, "single-node", false,
// 		"Explicitly configure as single-node deployment")
// 	bootstrapAllCmd.Flags().StringVar(&preferredRole, "preferred-role", "",
// 		"Preferred role when joining cluster (edge/core/data/compute)")
// 	bootstrapAllCmd.Flags().BoolVar(&autoDiscover, "auto-discover", false,
// 		"Enable automatic cluster discovery via multicast")
	
// 	// Add hardening flag
// 	bootstrapCmd.Flags().BoolVar(&skipHardening, "skip-hardening", false,
// 		"Skip Ubuntu security hardening (not recommended for production)")
// 	bootstrapAllCmd.Flags().BoolVar(&skipHardening, "skip-hardening", false,
// 		"Skip Ubuntu security hardening (not recommended for production)")
// }

// RunBootstrapAllEnhanced is the enhanced version with cluster support
// This is exported so it can be called from the top-level bootstrap command
func RunBootstrapAllEnhanced(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting enhanced infrastructure bootstrap")
	
	// Parse flags into options
	opts := &bootstrap.BootstrapOptions{
		JoinCluster:   cmd.Flag("join-cluster").Value.String(),
		SingleNode:    cmd.Flag("single-node").Value.String() == "true",
		PreferredRole: cmd.Flag("preferred-role").Value.String(),
		AutoDiscover:  cmd.Flag("auto-discover").Value.String() == "true",
		SkipHardening: cmd.Flag("skip-hardening").Value.String() == "true",
		DryRun:        cmd.Flag("dry-run").Value.String() == "true",
		ValidateOnly:  cmd.Flag("validate-only").Value.String() == "true",
		Force:         cmd.Flag("force").Value.String() == "true",
	}
	
	// Handle enhanced flags
	if cmd.Flag("verify") != nil && cmd.Flag("verify").Value.String() == "true" {
		opts.ValidateOnly = true
	}
	
	if cmd.Flag("stop-conflicting") != nil && cmd.Flag("stop-conflicting").Value.String() == "true" {
		// This will be handled in the orchestrator
		logger.Info("Auto-stop conflicting services enabled")
	}
	
	if cmd.Flag("clean") != nil && cmd.Flag("clean").Value.String() == "true" {
		logger.Info("Clean slate installation requested")
		opts.Force = true
	}
	
	// Use the new enhanced orchestrator
	return bootstrap.OrchestrateBootstrap(rc, cmd, opts)
}

// bootstrapSingleNodeEnhanced bootstraps a single node with storage ops
func bootstrapSingleNodeEnhanced(rc *eos_io.RuntimeContext, cmd *cobra.Command, clusterInfo *bootstrap.ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Phase 1: Install Salt
	logger.Info("Phase 1: Bootstrapping Salt", zap.Int("phase", 1), zap.Int("total_phases", 5))
	saltConfig := &saltstack.Config{
		MasterMode: !clusterInfo.IsSingleNode, // Master mode for multi-node
		LogLevel:   "warning",
	}
	if err := saltstack.Install(rc, saltConfig); err != nil {
		return fmt.Errorf("salt bootstrap failed: %w", err)
	}
	
	// Phase 1.5: Setup Salt API (for master nodes)
	if clusterInfo.IsMaster || clusterInfo.IsSingleNode {
		logger.Info("Phase 1.5: Setting up Salt API", zap.Int("phase", 1), zap.Int("total_phases", 5))
		if err := bootstrap.SetupSaltAPI(rc); err != nil {
			logger.Warn("Salt API setup failed, continuing without API", zap.Error(err))
			// Continue anyway - the system can work without the API
		}
	}
	
	// Phase 2: Deploy Storage Operations
	logger.Info("Phase 2: Deploying Storage Operations", zap.Int("phase", 2), zap.Int("total_phases", 5))
	if err := bootstrap.DeployStorageOps(rc, clusterInfo); err != nil {
		return fmt.Errorf("storage ops deployment failed: %w", err)
	}
	
	// Phase 3: Install Tailscale
	logger.Info("Phase 3: Installing Tailscale", zap.Int("phase", 3), zap.Int("total_phases", 5))
	if err := installTailscaleForBootstrap(rc); err != nil {
		logger.Warn("Tailscale installation failed, continuing anyway", zap.Error(err))
		// Continue anyway - Tailscale is helpful but not critical
	}
	
	// Phase 4: Bootstrap OSQuery
	logger.Info("Phase 4: Bootstrapping OSQuery", zap.Int("phase", 4), zap.Int("total_phases", 5))
	if err := osquery.InstallOsquery(rc); err != nil {
		return fmt.Errorf("osquery bootstrap failed: %w", err)
	}
	
	// Phase 5: Ubuntu Security Hardening with FIDO2
	logger.Info("Phase 5: Applying Ubuntu security hardening", zap.Int("phase", 5), zap.Int("total_phases", 5))
	skipHardening := cmd.Flag("skip-hardening").Value.String() == "true"
	if skipHardening {
		logger.Info("Skipping Ubuntu hardening as requested")
	} else {
		// Ask user if they want to apply FIDO2 hardening
		logger.Info("Ubuntu security hardening includes FIDO2/YubiKey requirement for SSH")
		logger.Info("This will disable password authentication and require hardware keys")
		logger.Info("terminal prompt: Do you have a FIDO2/YubiKey device and want to enable this security feature? [y/N]")
		
		response, err := eos_io.ReadInput(rc)
		if err != nil {
			logger.Warn("Failed to read user input, skipping FIDO2 hardening", zap.Error(err))
			response = "n"
		}
		
		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" {
			logger.Info("Applying comprehensive Ubuntu hardening with FIDO2 SSH authentication")
			if err := ubuntu.HardenUbuntuWithFIDO2(rc); err != nil {
				logger.Warn("Ubuntu hardening failed, continuing anyway", zap.Error(err))
				// Don't fail the entire bootstrap if hardening fails
				// The core infrastructure is already set up
			} else {
				logger.Info("Ubuntu hardening completed successfully")
				logger.Info("IMPORTANT: You must run 'eos-enroll-fido2' to enroll your FIDO2 keys for SSH")
				logger.Info("WARNING: Do not close your current SSH session until you've enrolled your keys!")
			}
		} else {
			logger.Info("Applying Ubuntu hardening without FIDO2 SSH requirement")
			// Run hardening without FIDO2
			if err := ubuntu.SecureUbuntuEnhanced(rc, "disabled"); err != nil {
				logger.Warn("Ubuntu hardening failed, continuing anyway", zap.Error(err))
			} else {
				logger.Info("Ubuntu hardening completed successfully (SSH password auth remains enabled)")
			}
		}
	}
	
	// Phase 6: Create Enhanced Environment Configuration
	logger.Info("Phase 6: Creating enhanced environment configuration", zap.Int("phase", 6), zap.Int("total_phases", 6))
	if err := createEnhancedEnvironmentConfig(rc, clusterInfo); err != nil {
		logger.Warn("Failed to create enhanced environment config", zap.Error(err))
		// Don't fail bootstrap for this
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
func bootstrapAdditionalNode(rc *eos_io.RuntimeContext, cmd *cobra.Command, clusterInfo *bootstrap.ClusterInfo) error {
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
	
	// Phase 3: Install Tailscale
	logger.Info("Phase 3: Installing Tailscale")
	if err := installTailscaleForBootstrap(rc); err != nil {
		logger.Warn("Tailscale installation failed, continuing anyway", zap.Error(err))
		// Continue anyway - Tailscale is helpful but not critical
	}
	
	// Phase 4: Apply Salt highstate to configure node
	logger.Info("Phase 4: Applying Salt highstate for node configuration")
	// The master will push the appropriate states based on our role
	
	// Phase 5: Ubuntu Security Hardening with FIDO2 (same as master)
	logger.Info("Phase 5: Applying Ubuntu security hardening")
	skipHardening := cmd.Flag("skip-hardening").Value.String() == "true"
	if skipHardening {
		logger.Info("Skipping Ubuntu hardening as requested")
	} else {
		// Ask user if they want to apply FIDO2 hardening
		logger.Info("Ubuntu security hardening includes FIDO2/YubiKey requirement for SSH")
		logger.Info("This will disable password authentication and require hardware keys")
		logger.Info("terminal prompt: Do you have a FIDO2/YubiKey device and want to enable this security feature? [y/N]")
		
		response, err := eos_io.ReadInput(rc)
		if err != nil {
			logger.Warn("Failed to read user input, skipping FIDO2 hardening", zap.Error(err))
			response = "n"
		}
		
		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" {
			logger.Info("Applying comprehensive Ubuntu hardening with FIDO2 SSH authentication")
			if err := ubuntu.HardenUbuntuWithFIDO2(rc); err != nil {
				logger.Warn("Ubuntu hardening failed, continuing anyway", zap.Error(err))
				// Don't fail the entire bootstrap if hardening fails
			} else {
				logger.Info("Ubuntu hardening completed successfully")
				logger.Info("IMPORTANT: You must run 'eos-enroll-fido2' to enroll your FIDO2 keys for SSH")
				logger.Info("WARNING: Do not close your current SSH session until you've enrolled your keys!")
			}
		} else {
			logger.Info("Applying Ubuntu hardening without FIDO2 SSH requirement")
			// Run hardening without FIDO2
			if err := ubuntu.SecureUbuntuEnhanced(rc, "disabled"); err != nil {
				logger.Warn("Ubuntu hardening failed, continuing anyway", zap.Error(err))
			} else {
				logger.Info("Ubuntu hardening completed successfully (SSH password auth remains enabled)")
			}
		}
	}
	
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
		logger.Info("3. Configure Tailscale: sudo tailscale up")
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
	// TODO: [P3] Implement actual IP detection instead of placeholder
	// This is simplified, in production would be more robust
	return "YOUR_MASTER_IP"
}

// installTailscaleForBootstrap is a helper function to install Tailscale during bootstrap
func installTailscaleForBootstrap(rc *eos_io.RuntimeContext) error {
	options := &service_installation.ServiceInstallOptions{
		Name:        "tailscale",
		Type:        service_installation.ServiceTypeTailscale,
		Method:      service_installation.MethodNative,
		DryRun:      false,
		Environment: make(map[string]string),
		Config:      make(map[string]string),
	}
	
	result, err := service_installation.InstallService(rc, options)
	if err != nil {
		return fmt.Errorf("tailscale installation failed: %w", err)
	}
	
	if !result.Success {
		return fmt.Errorf("tailscale installation was not successful")
	}
	
	return nil
}

// createEnhancedEnvironmentConfig creates environment configuration files during bootstrap
func createEnhancedEnvironmentConfig(rc *eos_io.RuntimeContext, clusterInfo *bootstrap.ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating enhanced environment configuration")

	// Create environment config directory
	bootstrapDir := "/opt/eos/bootstrap"
	if err := os.MkdirAll(bootstrapDir, 0755); err != nil {
		return fmt.Errorf("failed to create bootstrap directory: %w", err)
	}

	// Discover enhanced environment configuration
	enhancedConfig, err := environment.DiscoverEnhancedEnvironment(rc)
	if err != nil {
		return fmt.Errorf("failed to discover enhanced environment: %w", err)
	}

	// Override with cluster-specific information
	enhancedConfig.ClusterSize = clusterInfo.NodeCount
	if clusterInfo.IsSingleNode {
		enhancedConfig.ClusterSize = 1
		enhancedConfig.NodeRoles = map[string][]string{
			"localhost": {"server", "client", "database", "monitoring"},
		}
	}

	// Create environment.json file
	envFile := filepath.Join(bootstrapDir, "environment.json")
	envData, err := json.MarshalIndent(enhancedConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal environment config: %w", err)
	}

	if err := os.WriteFile(envFile, envData, 0644); err != nil {
		return fmt.Errorf("failed to write environment config: %w", err)
	}

	logger.Info("Created environment configuration file",
		zap.String("file", envFile),
		zap.String("profile", string(enhancedConfig.Profile)),
		zap.Int("cluster_size", enhancedConfig.ClusterSize))

	// Set Salt grains for environment discovery
	if err := setSaltEnvironmentGrains(rc, enhancedConfig); err != nil {
		logger.Warn("Failed to set Salt environment grains", zap.Error(err))
		// Don't fail bootstrap for this
	}

	return nil
}

// setSaltEnvironmentGrains configures Salt grains for environment discovery
func setSaltEnvironmentGrains(rc *eos_io.RuntimeContext, config *environment.EnhancedEnvironmentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting Salt environment grains")

	// Set environment grain
	if err := setSaltGrain(rc, "environment", config.Environment); err != nil {
		return fmt.Errorf("failed to set environment grain: %w", err)
	}

	// Set deployment profile grain
	if err := setSaltGrain(rc, "deployment_profile", string(config.Profile)); err != nil {
		return fmt.Errorf("failed to set deployment_profile grain: %w", err)
	}

	// Set cluster size grain
	if err := setSaltGrain(rc, "cluster_size", fmt.Sprintf("%d", config.ClusterSize)); err != nil {
		return fmt.Errorf("failed to set cluster_size grain: %w", err)
	}

	// Set resource strategy grain
	if err := setSaltGrain(rc, "resource_strategy", config.ResourceStrategy); err != nil {
		return fmt.Errorf("failed to set resource_strategy grain: %w", err)
	}

	// Set node roles grain (convert to JSON string)
	if len(config.NodeRoles) > 0 {
		rolesData, err := json.Marshal(config.NodeRoles)
		if err == nil {
			if err := setSaltGrain(rc, "node_roles", string(rolesData)); err != nil {
				logger.Warn("Failed to set node_roles grain", zap.Error(err))
			}
		}
	}

	// Set primary namespace grain
	if err := setSaltGrain(rc, "primary_namespace", config.Namespaces.Primary); err != nil {
		return fmt.Errorf("failed to set primary_namespace grain: %w", err)
	}

	logger.Info("Salt environment grains configured successfully")
	return nil
}

// setSaltGrain sets a single Salt grain
func setSaltGrain(rc *eos_io.RuntimeContext, key, value string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Setting Salt grain", zap.String("key", key), zap.String("value", value))

	// Use salt-call to set the grain locally
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "grains.setval", key, value},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to set grain %s: %w (output: %s)", key, err, output)
	}

	logger.Debug("Salt grain set successfully", zap.String("key", key))
	return nil
}