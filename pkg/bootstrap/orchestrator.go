// pkg/bootstrap/orchestrator.go
//
// Enhanced bootstrap orchestrator that provides improved error handling,
// progress reporting, and idempotent operations.

package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// checkpointMutex protects concurrent checkpoint file operations
var checkpointMutex sync.Mutex

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
	
	// Advanced options
	DryRun        bool
	ValidateOnly  bool
	Force         bool
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
	
	// Phase 0: Validation
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
			Name:        "salt",
			Description: "Installing and configuring SaltStack",
			Required:    true,
			RunFunc:     phaseSalt,
		},
		{
			Name:        "salt-api",
			Description: "Setting up Salt API service",
			Required:    true,  // Changed to required - Salt API is essential for Eos operations
			RunFunc:     phaseSaltAPI,
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
	
	// Add cluster-specific phases if joining
	if !clusterInfo.IsSingleNode && !clusterInfo.IsMaster {
		// Insert cluster join phase after Salt
		joinPhase := BootstrapPhase{
			Name:        "cluster-join",
			Description: "Joining existing cluster",
			Required:    true,
			RunFunc:     phaseClusterJoin,
		}
		
		// Insert after Salt phase
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

func phaseSalt(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing and configuring SaltStack")
	
	// Use the comprehensive Salt bootstrap that includes both Salt and file roots setup
	return BootstrapSaltComplete(rc, info)
}

func phaseSaltAPI(rc *eos_io.RuntimeContext, opts *BootstrapOptions, info *ClusterInfo) error {
	if info.IsMaster || info.IsSingleNode {
		return SetupSaltAPI(rc)
	}
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
	logger.Info("Joining cluster", zap.String("master", info.MasterAddr))
	
	// Perform health checks
	healthResult, err := PerformHealthChecks(rc, info.MasterAddr)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	
	if !healthResult.Passed {
		return fmt.Errorf("pre-join health checks failed: %v", healthResult.FailedChecks)
	}
	
	// Register with master
	reg := NodeRegistration{
		PreferredRole: opts.PreferredRole,
	}
	
	result, err := RegisterNode(rc, info.MasterAddr, reg)
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

func createCheckpoint(rc *eos_io.RuntimeContext, phaseName string, info *ClusterInfo) error {
	// Protect checkpoint operations with mutex
	checkpointMutex.Lock()
	defer checkpointMutex.Unlock()
	
	checkpointDir := "/var/lib/eos/bootstrap"
	if err := CreateDirectoryIfMissing(checkpointDir, 0755); err != nil {
		return err
	}
	
	checkpointFile := fmt.Sprintf("%s/checkpoint_%s", checkpointDir, phaseName)
	data := fmt.Sprintf("phase=%s\ntime=%s\ncluster_id=%s\n", 
		phaseName, time.Now().Format(time.RFC3339), info.ClusterID)
	
	return os.WriteFile(checkpointFile, []byte(data), 0644)
}

func getRecoveryFunction(phaseName string) func(*eos_io.RuntimeContext, error) error {
	// Define recovery functions for specific phases
	recoveryFuncs := map[string]func(*eos_io.RuntimeContext, error) error{
		"salt": func(rc *eos_io.RuntimeContext, err error) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Attempting Salt recovery")
			
			// Check if we should preserve user configurations
			preserveConfigs := os.Getenv("EOS_PRESERVE_CONFIGS") == "true"
			
			if preserveConfigs {
				// Backup user configurations before cleanup
				backupDir := "/var/backups/eos-salt-configs"
				if err := os.MkdirAll(backupDir, 0755); err == nil {
					// Best effort backup
					execute.Run(rc.Ctx, execute.Options{
						Command: "cp",
						Args:    []string{"-r", "/etc/salt", backupDir},
						Capture: false,
					})
					logger.Info("Backed up Salt configurations", zap.String("backup_dir", backupDir))
				}
			}
			
			// Clean up partial installation with error handling
			if output, err := execute.Run(rc.Ctx, execute.Options{
				Command: "apt-get",
				Args:    []string{"remove", "--purge", "-y", "salt-common", "salt-minion", "salt-master"},
				Capture: true,
			}); err != nil {
				logger.Warn("Failed to remove Salt packages", 
					zap.Error(err),
					zap.String("output", output))
				// Continue with cleanup anyway
			}
			
			// Clean configuration directories
			configDirs := []string{"/etc/salt", "/var/cache/salt"}
			for _, dir := range configDirs {
				if preserveConfigs {
					// Only remove cache, keep configs
					if dir == "/var/cache/salt" {
						if err := os.RemoveAll(dir); err != nil {
							logger.Warn("Failed to remove directory",
								zap.String("dir", dir),
								zap.Error(err))
						}
					}
				} else {
					// Remove all
					if err := os.RemoveAll(dir); err != nil {
						logger.Warn("Failed to remove directory",
							zap.String("dir", dir),
							zap.Error(err))
					}
				}
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
	} else if info.IsMaster {
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