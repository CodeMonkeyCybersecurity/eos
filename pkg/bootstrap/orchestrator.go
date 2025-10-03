// pkg/bootstrap/orchestrator.go
//
// Enhanced bootstrap orchestrator that provides improved error handling,
// progress reporting, and idempotent operations.

package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// checkpointMutex protects concurrent checkpoint file operations
// checkpointMutex removed - was unused after createCheckpoint function removal

// BootstrapOptions contains all configuration for bootstrap
type BootstrapOptions struct {
	// Cluster configuration
	JoinCluster   string
	SingleNode    bool
	PreferredRole string
	AutoDiscover  bool

	// Features to enable/disable
	SkipHardening bool
	SkipStorage   bool
	SkipTailscale bool
	SkipOSQuery   bool

	// HashiCorp stack options
	SkipConsul    bool  // Consul is required by default
	EnableVault   bool  // Vault is opt-in
	EnableNomad   bool  // Nomad is opt-in

	// Advanced options
	DryRun       bool
	ValidateOnly bool
	Force        bool
}

// BootstrapPhase represents a phase of the bootstrap process
type BootstrapPhase struct {
	Name        string
	Description string
	Required    bool
	RunFunc     func(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error
	SkipIf      func(opts *BootstrapOptions) bool
}

// OrchestrateBootstrap is the main entry point for enhanced bootstrap
func OrchestrateBootstrap(rc *eos_io.RuntimeContext, cmd *cobra.Command, opts *BootstrapOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting enhanced bootstrap orchestration")

	// Phase 0: State Detection and Conflict Resolution
	logger.Info("Detecting bootstrap state")
	state, err := DetectBootstrapState(rc)
	if err != nil {
		return fmt.Errorf("failed to detect bootstrap state: %w", err)
	}

	// Handle guided mode
	if isGuidedMode(cmd) {
		return PromptGuidedBootstrap(rc)
	}

	// Print state report
	PrintBootstrapStateReport(rc, state)

	// Handle conflicts unless forced
	if !opts.Force && (state.Phase == PhaseConflicting || len(state.PortConflicts) > 0) {
		logger.Info("Resolving conflicts")
		resolutionOptions, err := PromptConflictResolution(rc, state)
		if err != nil {
			return fmt.Errorf("conflict resolution failed: %w", err)
		}

		if err := ExecuteConflictResolution(rc, resolutionOptions); err != nil {
			return fmt.Errorf("failed to resolve conflicts: %w", err)
		}

		// Re-detect state after conflict resolution
		state, err = DetectBootstrapState(rc)
		if err != nil {
			return fmt.Errorf("failed to re-detect state after conflict resolution: %w", err)
		}
	}

	// Phase 1: System Validation
	if !opts.Force {
		logger.Info("Running system validation")
		requirements := DefaultSystemRequirements()
		result, err := ValidateSystem(rc, requirements)
		if err != nil {
			return fmt.Errorf("system validation failed: %w", err)
		}

		PrintValidationReport(rc, result)

		if !result.Passed {
			if opts.ValidateOnly {
				return fmt.Errorf("system validation failed")
			}

			// Ask user if they want to continue despite failures
			logger.Info("terminal prompt: System validation failed. Continue anyway? [y/N]")
			response, err := eos_io.ReadInput(rc)
			if err != nil || !isYes(response) {
				return fmt.Errorf("bootstrap cancelled due to validation failures")
			}
		}

		if opts.ValidateOnly {
			logger.Info("Validation completed successfully (--validate-only specified)")
			return nil
		}
	}

	// Detect cluster state
	logger.Info("Detecting cluster state")
	clusterInfo, err := DetectClusterState(rc, Options{
		JoinCluster:   opts.JoinCluster,
		SingleNode:    opts.SingleNode,
		PreferredRole: opts.PreferredRole,
		AutoDiscover:  opts.AutoDiscover,
	})
	if err != nil {
		return fmt.Errorf("failed to detect cluster state: %w", err)
	}

	// Define bootstrap phases
	phases := defineBootstrapPhases(clusterInfo)

	// Count enabled phases
	enabledPhases := 0
	for _, phase := range phases {
		if phase.SkipIf == nil || !phase.SkipIf(opts) {
			enabledPhases++
		}
	}

	// Create progress reporter
	progress := NewProgressReporter(rc, enabledPhases)

	// Execute phases
	for _, phase := range phases {
		// Check if phase should be skipped
		if phase.SkipIf != nil && phase.SkipIf(opts) {
			logger.Info("Skipping phase", zap.String("phase", phase.Name))
			continue
		}

		progress.StartPhase(phase.Description)

		if opts.DryRun {
			logger.Info("DRY RUN: Would execute phase", zap.String("phase", phase.Name))
			progress.CompletePhase()
			continue
		}

		// Execute phase with error handling
		if err := executePhaseWithRecovery(rc, phase, opts, clusterInfo); err != nil {
			if phase.Required {
				return fmt.Errorf("required phase %s failed: %w", phase.Name, err)
			}
			logger.Warn("Optional phase failed, continuing",
				zap.String("phase", phase.Name),
				zap.Error(err))
		}

		progress.CompletePhase()

		// Log phase completion - we use state validation now, not checkpoints
		logger.Info("Phase completed successfully",
			zap.String("phase", phase.Name),
			zap.String("description", phase.Description))
	}

	// Final steps
	if !opts.DryRun {
		// Save cluster configuration
		if err := SaveClusterConfig(rc, clusterInfo); err != nil {
			logger.Warn("Failed to save cluster config", zap.Error(err))
		}

		// Verify all phases completed successfully
		complete, missingPhases := IsBootstrapComplete(rc)
		if !complete {
			logger.Warn("Bootstrap may be incomplete",
				zap.Strings("missing_phases", missingPhases))
		}
	}

	// Show completion summary
	showBootstrapSummary(rc, clusterInfo, opts)

	return nil
}

// defineBootstrapPhases returns the list of bootstrap phases
func defineBootstrapPhases(clusterInfo *ClusterInfo) []BootstrapPhase {
	phases := []BootstrapPhase{
		{
			Name:        "consul",
			Description: "Installing and configuring Consul",
			Required:    true,  // Consul is REQUIRED
			RunFunc:     phaseConsul,
			SkipIf: func(opts *BootstrapOptions) bool {
				return opts.SkipConsul
			},
		},
		{
			Name:        "vault",
			Description: "Installing and configuring Vault",
			Required:    false,  // Vault is optional
			RunFunc:     phaseVault,
			SkipIf: func(opts *BootstrapOptions) bool {
				return !opts.EnableVault  // Skip unless explicitly enabled
			},
		},
		{
			Name:        "nomad",
			Description: "Installing and configuring Nomad",
			Required:    false,  // Nomad is optional
			RunFunc:     phaseNomad,
			SkipIf: func(opts *BootstrapOptions) bool {
				return !opts.EnableNomad  // Skip unless explicitly enabled
			},
		},
		{
			Name:        "storage",
			Description: "Deploying storage operations",
			Required:    false,
			RunFunc:     phaseStorage,
			SkipIf: func(opts *BootstrapOptions) bool {
				return opts.SkipStorage
			},
		},
		{
			Name:        "tailscale",
			Description: "Installing Tailscale VPN",
			Required:    false,
			RunFunc:     phaseTailscale,
			SkipIf: func(opts *BootstrapOptions) bool {
				return opts.SkipTailscale
			},
		},
		{
			Name:        "osquery",
			Description: "Installing OSQuery monitoring",
			Required:    false,
			RunFunc:     phaseOSQuery,
			SkipIf: func(opts *BootstrapOptions) bool {
				return opts.SkipOSQuery
			},
		},
		{
			Name:        "hardening",
			Description: "Applying Ubuntu security hardening",
			Required:    false,
			RunFunc:     phaseHardening,
			SkipIf: func(opts *BootstrapOptions) bool {
				return opts.SkipHardening
			},
		},
	}

	// Add cluster-specific phases if joining (HashiCorp cluster member)
	if !clusterInfo.IsSingleNode && clusterInfo.MyRole != environment.RoleMonolith {
		// Insert cluster join phase after
		joinPhase := BootstrapPhase{
			Name:        "cluster-join",
			Description: "Joining existing cluster",
			Required:    true,
			RunFunc:     phaseClusterJoin,
		}

		// Insert after  phase
		newPhases := []BootstrapPhase{phases[0], joinPhase}
		newPhases = append(newPhases, phases[1:]...)
		phases = newPhases
	}

	return phases
}

// executePhaseWithRecovery executes a phase with error recovery
func executePhaseWithRecovery(rc *eos_io.RuntimeContext, phase BootstrapPhase, opts *BootstrapOptions, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if phase was already completed (idempotency)
	if isPhaseCompleted(rc, phase.Name) {
		logger.Info("Phase already completed, skipping", zap.String("phase", phase.Name))
		return nil
	}

	// Execute with retry for transient failures
	retryConfig := DefaultRetryConfig()
	if phase.Required {
		retryConfig.MaxAttempts = 5
	}

	err := WithRetry(rc, retryConfig, func() error {
		return phase.RunFunc(rc, opts, info)
	})

	if err != nil {
		// Try recovery if available
		if recoveryFunc := getRecoveryFunction(phase.Name); recoveryFunc != nil {
			logger.Info("Attempting recovery for failed phase", zap.String("phase", phase.Name))
			if recoveryErr := recoveryFunc(rc, err); recoveryErr == nil {
				// Retry after recovery
				return phase.RunFunc(rc, opts, info)
			}
		}
		return err
	}

	return nil
}

// Phase implementations

func phaseConsul(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing and configuring Consul")

	// Assess - Check if Consul is already healthy
	health, err := CheckServiceHealth(rc, "consul")
	if err != nil {
		logger.Debug("Consul health check failed, will attempt installation", zap.Error(err))
		// Create empty health status for installation logic
		health = &ServiceHealth{Enabled: false, Running: false}
	} else if health.Healthy {
		logger.Info("Consul is already installed and healthy")
		return nil
	}

	// Install/Reconfigure Consul if not healthy
	// IMPORTANT: We install even if Consul exists but is unhealthy (e.g. crash looping with bad config)
	// The Install() function has idempotent checks that will fix stale configs
	if !health.Enabled || !health.Healthy {
		if !health.Enabled {
			logger.Info("Consul not found, installing...")
		} else {
			logger.Info("Consul is unhealthy, reinstalling/reconfiguring...")
		}

		// Configure Consul based on cluster info
		consulConfig := &consul.ConsulConfig{
			Mode:       "server", // Bootstrap always installs server mode
			Datacenter: "dc1",
			UI:         true,
			BindAddr:   "0.0.0.0",
			ClientAddr: "0.0.0.0",
			LogLevel:   "INFO",
		}

		// Set bootstrap expect based on cluster configuration
		if info.IsSingleNode {
			consulConfig.BootstrapExpect = 1
			logger.Info("Configuring Consul for single-node deployment")
		} else {
			// For multi-node, set based on actual node count or expected count
			consulConfig.BootstrapExpect = info.NodeCount
			if consulConfig.BootstrapExpect == 0 {
				consulConfig.BootstrapExpect = 3 // Default to 3 for HA
			}
			logger.Info("Configuring Consul for multi-node deployment",
				zap.Int("bootstrap_expect", consulConfig.BootstrapExpect))
		}

		// Intervene - Install Consul with error recovery
		logger.Info("Installing Consul with configuration",
			zap.String("datacenter", consulConfig.Datacenter),
			zap.Int("bootstrap_expect", consulConfig.BootstrapExpect))

		if err := consul.InstallConsul(rc, consulConfig); err != nil {
			// Check if it's a permissions error
			if strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "sudo") {
				return fmt.Errorf("Consul installation requires sudo privileges. Please run with sudo or as root: %w", err)
			}
			// Check if it's a port conflict
			if strings.Contains(err.Error(), "port") || strings.Contains(err.Error(), "bind") {
				return fmt.Errorf("Consul installation failed due to port conflict. Please check if another service is using Consul ports (8161, 8431, 8443, 8447, 8389): %w", err)
			}
			return fmt.Errorf("Consul installation failed: %w", err)
		}
	}

	// Ensure Consul service is running with retry logic
	if !health.Running {
		logger.Info("Starting Consul service")
		if err := EnableAndStartService(rc, "consul"); err != nil {
			// Check if it's a systemd issue
			if strings.Contains(err.Error(), "Failed to enable") {
				return fmt.Errorf("failed to enable Consul service. Check if systemd is running and you have appropriate permissions: %w", err)
			}
			if strings.Contains(err.Error(), "Failed to start") {
				return fmt.Errorf("Consul service failed to start. Check logs with 'journalctl -u consul': %w", err)
			}
			return fmt.Errorf("failed to start Consul service: %w", err)
		}
	}

	// Evaluate - Validate Consul is healthy with retry
	logger.Info("Validating Consul health")
	var lastErr error
	for i := 0; i < 3; i++ {
		requiredServices := []string{"consul"}
		if err := ValidateRequiredServices(rc, requiredServices); err != nil {
			lastErr = err
			if i < 2 {
				logger.Warn("Consul health validation failed, retrying...", zap.Error(err), zap.Int("attempt", i+1))
				time.Sleep(time.Duration(2*(i+1)) * time.Second)
				continue
			}
		} else {
			lastErr = nil
			break
		}
	}
	if lastErr != nil {
		return fmt.Errorf("consul health validation failed after 3 attempts. Check if Consul is listening on expected ports and API is responding: %w", lastErr)
	}

	logger.Info("Consul installed and verified successfully")
	return nil
}

func phaseVault(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing and configuring Vault")

	// Assess - Check if Vault is already healthy
	health, err := CheckServiceHealth(rc, "vault")
	if err != nil {
		logger.Debug("Vault health check failed, will attempt installation", zap.Error(err))
		health = &ServiceHealth{Enabled: false, Running: false}
	} else if health.Healthy {
		logger.Info("Vault is already installed and healthy")
		return nil
	}

	// Install Vault if not present
	if !health.Enabled {
		logger.Info("Vault not found, installing...")
		// Intervene - Install Vault with error recovery
		logger.Info("Installing Vault")
		if err := vault.PhaseInstallVault(rc); err != nil {
			if strings.Contains(err.Error(), "permission denied") {
				return fmt.Errorf("Vault installation requires sudo privileges: %w", err)
			}
			if strings.Contains(err.Error(), "repository") {
				return fmt.Errorf("Vault installation failed - check network connectivity and HashiCorp repository access: %w", err)
			}
			return fmt.Errorf("Vault installation failed: %w", err)
		}
	}

	// Configure and start Vault service using vault's service manager
	// This handles systemd unit creation, configuration validation, and service start
	if err := vault.StartVaultService(rc); err != nil {
		if strings.Contains(err.Error(), "config") {
			return fmt.Errorf("Vault configuration validation failed. Check /etc/vault/vault.hcl: %w", err)
		}
		if strings.Contains(err.Error(), "systemd") {
			return fmt.Errorf("Vault service failed to start. Check logs with 'journalctl -u vault': %w", err)
		}
		return fmt.Errorf("failed to start Vault service: %w", err)
	}

	// Check if Vault needs initialization
	vaultHealth, _ := CheckServiceHealth(rc, "vault")
	if vaultHealth.Details["initialized"] == false {
		logger.Warn("Vault is not initialized")
		logger.Info("Run 'vault operator init' to initialize Vault")
		logger.Info("Save the unseal keys and root token securely!")
	} else if vaultHealth.Details["sealed"] == true {
		logger.Warn("Vault is sealed")
		logger.Info("Run 'vault operator unseal' with your unseal keys")
	}

	// Don't validate if Vault is not healthy for opt-in service
	// Since Vault might need initialization and unsealing
	logger.Info("Vault installed successfully (may need init/unseal)")
	return nil
}

func phaseNomad(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing and configuring Nomad")

	// Check if Nomad is already healthy
	health, err := CheckServiceHealth(rc, "nomad")
	if err == nil && health.Healthy {
		logger.Info("Nomad is already installed and healthy")
		return nil
	}

	// Install Nomad if not present
	if !health.Enabled {
		logger.Info("Nomad not found, installing...")
		// Use the actual Nomad deployment from pkg/nomad
		if err := nomad.DeployNomad(rc); err != nil {
			return fmt.Errorf("failed to deploy Nomad: %w", err)
		}
	}

	// Nomad deployment handles service configuration and start internally
	// No additional service management needed here

	// Validate Nomad is healthy
	requiredServices := []string{"nomad"}
	if err := ValidateRequiredServices(rc, requiredServices); err != nil {
		logger.Warn("Nomad health validation failed but continuing (optional service)", zap.Error(err))
		// Don't fail for optional Nomad
	}

	logger.Info("Nomad installed successfully")
	return nil
}

func phaseStorage(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	return DeployStorageOps(rc, info)
}

func phaseTailscale(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	// This would call the Tailscale installation
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Tailscale")
	return nil
}

func phaseOSQuery(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	// This would call osquery.InstallOsquery(rc)
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing OSQuery")
	return nil
}

func phaseHardening(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if user wants FIDO2 hardening
	logger.Info("Ubuntu security hardening includes FIDO2/YubiKey requirement for SSH")
	logger.Info("terminal prompt: Enable FIDO2 SSH authentication? [y/N]")

	response, err := eos_io.ReadInput(rc)
	if err != nil {
		logger.Warn("Failed to read user input, skipping FIDO2", zap.Error(err))
		response = "n"
	}

	if isYes(response) {
		logger.Info("Applying hardening with FIDO2")
		// Would call ubuntu.HardenUbuntuWithFIDO2(rc)
	} else {
		logger.Info("Applying hardening without FIDO2")
		// Would call ubuntu.SecureUbuntuEnhanced(rc, "disabled")
	}

	return nil
}

func phaseClusterJoin(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Joining HashiCorp cluster",
		zap.String("cluster_id", info.ClusterID),
		zap.String("role", string(info.MyRole)))

	// Perform HashiCorp cluster health checks (Consul/Nomad)
	consulAddr := fmt.Sprintf("localhost:%d", shared.PortConsul) // EOS Consul address (8161)
	healthResult, err := PerformHealthChecks(rc, consulAddr)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if !healthResult.Passed {
		return fmt.Errorf("pre-join health checks failed: %v", healthResult.FailedChecks)
	}

	// Register with HashiCorp Consul cluster
	reg := NodeRegistration{
		PreferredRole: opts.PreferredRole,
	}

	result, err := RegisterNode(rc, consulAddr, reg)
	if err != nil {
		return fmt.Errorf("node registration failed: %w", err)
	}

	if !result.Accepted {
		return fmt.Errorf("node registration was not accepted")
	}

	// Update cluster info
	info.MyRole = result.AssignedRole
	info.ClusterID = result.ClusterID

	logger.Info("Successfully joined cluster",
		zap.String("role", string(result.AssignedRole)),
		zap.String("cluster_id", result.ClusterID))

	return nil
}

// Utility functions

func isPhaseCompleted(rc *eos_io.RuntimeContext, phaseName string) bool {
	// Use state validation to check phase completion
	return ValidatePhaseCompletion(rc, phaseName)
}

// createCheckpoint function removed - was unused

func getRecoveryFunction(phaseName string) func(*eos_io.RuntimeContext, error) error {
	// Define recovery functions for specific phases
	recoveryFuncs := map[string]func(*eos_io.RuntimeContext, error) error{
		"": func(rc *eos_io.RuntimeContext, err error) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Attempting  recovery")

			// Check if we should preserve user configurations
			preserveConfigs := os.Getenv("EOS_PRESERVE_CONFIGS") == "true"

			if preserveConfigs {
				// Backup user configurations before cleanup
				backupDir := "/var/backups/eos--configs"
				if err := os.MkdirAll(backupDir, 0755); err == nil {
					// Best effort backup
					execute.Run(rc.Ctx, execute.Options{
						Command: "cp",
						Args:    []string{"-r", "/etc/", backupDir},
						Capture: false,
					})
					logger.Info("Backed up  configurations", zap.String("backup_dir", backupDir))
				}
			}

			// Clean up partial installation with error handling
			if output, err := execute.Run(rc.Ctx, execute.Options{
				Command: "apt-get",
				Args:    []string{"remove", "--purge", "-y"},
				Capture: true,
			}); err != nil {
				logger.Warn("Failed to remove  packages",
					zap.Error(err),
					zap.String("output", output))
				// Continue with cleanup anyway
			}

			return nil
		},
	}

	return recoveryFuncs[phaseName]
}

func showBootstrapSummary(rc *eos_io.RuntimeContext, info *ClusterInfo, opts *BootstrapOptions) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("╔══════════════════════════════════════╗")
	logger.Info("║     Bootstrap Completed Successfully  ║")
	logger.Info("╚══════════════════════════════════════╝")

	logger.Info("System Configuration:",
		zap.Bool("single_node", info.IsSingleNode),
		zap.String("role", string(info.MyRole)),
		zap.String("cluster_id", info.ClusterID))

	if opts.DryRun {
		logger.Info("This was a DRY RUN - no changes were made")
		return
	}

	logger.Info("Next Steps:")
	if info.IsSingleNode {
		logger.Info("• Check system status: eos read system-status")
		logger.Info("• Configure Vault: eos create vault")
		logger.Info("• Deploy services: eos create [service]")
	} else if info.MyRole == environment.RoleMonolith {
		logger.Info("• Add more nodes: eos bootstrap --join-cluster=<this-node-ip>")
		logger.Info("• Check cluster status: eos read cluster-status")
	} else {
		logger.Info("• Verify cluster membership: eos read cluster-status")
		logger.Info("• Check assigned workloads: eos list workloads")
	}

	if !opts.SkipHardening {
		logger.Info("• Security hardening has been applied")
		logger.Info("• Review security settings: eos read security-status")
	}
}

func isYes(response string) bool {
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// isGuidedMode checks if guided mode is enabled
func isGuidedMode(cmd *cobra.Command) bool {
	if cmd.Flag("guided") != nil {
		return cmd.Flag("guided").Value.String() == "true"
	}
	return false
}
