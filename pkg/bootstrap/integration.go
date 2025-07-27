// pkg/bootstrap/integration.go
//
// Integration layer between the refactored bootstrap system and existing commands.
// This file provides compatibility functions to work with the current command structure.

package bootstrap

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunEnhancedBootstrap is the entry point for the enhanced bootstrap system
// that can be called from existing bootstrap commands.
func RunEnhancedBootstrap(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting enhanced bootstrap process")
	
	// Parse flags into options
	opts := &BootstrapOptions{
		JoinCluster:   getStringFlag(cmd, "join-cluster"),
		SingleNode:    getBoolFlag(cmd, "single-node"),
		PreferredRole: getStringFlag(cmd, "preferred-role"),
		AutoDiscover:  getBoolFlag(cmd, "auto-discover"),
		SkipHardening: getBoolFlag(cmd, "skip-hardening"),
		SkipStorage:   getBoolFlag(cmd, "skip-storage"),
		SkipTailscale: getBoolFlag(cmd, "skip-tailscale"),
		SkipOSQuery:   getBoolFlag(cmd, "skip-osquery"),
		DryRun:        getBoolFlag(cmd, "dry-run"),
		ValidateOnly:  getBoolFlag(cmd, "validate-only"),
		Force:         getBoolFlag(cmd, "force"),
	}
	
	// Check if system is already bootstrapped
	if !opts.Force && IsSystemBootstrapped() {
		logger.Info("System is already bootstrapped")
		logger.Info("Use --force to re-run bootstrap")
		return nil
	}
	
	// Run the enhanced orchestrator
	return OrchestrateBootstrap(rc, cmd, opts)
}

// RunComponentBootstrap runs bootstrap for a specific component
func RunComponentBootstrap(rc *eos_io.RuntimeContext, component string, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running component bootstrap", zap.String("component", component))
	
	// For component-specific bootstrap, we run with limited phases
	opts := &BootstrapOptions{
		SingleNode: true, // Component bootstrap assumes single node
		Force:      true, // Skip already-bootstrapped check for components
	}
	
	// Disable all optional components except the requested one
	opts.SkipHardening = true
	opts.SkipStorage = true
	opts.SkipTailscale = true
	opts.SkipOSQuery = true
	
	// Enable only the requested component
	switch component {
	case "salt":
		// Only Salt will run
	case "vault":
		// This would need to ensure Salt is installed first
		return fmt.Errorf("vault bootstrap not yet implemented in refactored version")
	case "nomad":
		// This would need to ensure Salt is installed first
		return fmt.Errorf("nomad bootstrap not yet implemented in refactored version")
	case "osquery":
		opts.SkipOSQuery = false
	default:
		return fmt.Errorf("unknown component: %s", component)
	}
	
	return OrchestrateBootstrap(rc, cmd, opts)
}

// MigrateToRefactoredBootstrap provides a migration path from old to new bootstrap
func MigrateToRefactoredBootstrap(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Migrating to refactored bootstrap system")
	
	// Check for old bootstrap markers
	oldMarkers := []string{
		"/opt/eos/.bootstrapped",
		"/etc/eos/bootstrap.conf",
		"/var/lib/eos/bootstrapped",
	}
	
	hasOldBootstrap := false
	for _, marker := range oldMarkers {
		if _, err := os.Stat(marker); err == nil {
			hasOldBootstrap = true
			logger.Info("Found old bootstrap marker", zap.String("file", marker))
		}
	}
	
	if !hasOldBootstrap {
		logger.Info("No old bootstrap found, nothing to migrate")
		return nil
	}
	
	// Create new checkpoint files for completed phases
	phases := []string{"salt", "vault", "nomad", "osquery"}
	for _, phase := range phases {
		// Check if the component is installed
		if isComponentInstalled(rc, phase) {
			logger.Info("Creating checkpoint for installed component", zap.String("phase", phase))
			if err := createCheckpoint(rc, phase, &ClusterInfo{}); err != nil {
				logger.Warn("Failed to create checkpoint", 
					zap.String("phase", phase),
					zap.Error(err))
			}
		}
	}
	
	logger.Info("Migration completed")
	return nil
}

// Helper functions

func getStringFlag(cmd *cobra.Command, name string) string {
	if cmd.Flag(name) != nil {
		return cmd.Flag(name).Value.String()
	}
	return ""
}

func getBoolFlag(cmd *cobra.Command, name string) bool {
	if cmd.Flag(name) != nil {
		return cmd.Flag(name).Value.String() == "true"
	}
	return false
}

func isComponentInstalled(rc *eos_io.RuntimeContext, component string) bool {
	switch component {
	case "salt":
		status, _ := CheckService(rc, "salt-minion")
		return status == ServiceStatusActive
	case "vault":
		status, _ := CheckService(rc, "vault")
		return status == ServiceStatusActive
	case "nomad":
		status, _ := CheckService(rc, "nomad")
		return status == ServiceStatusActive
	case "osquery":
		status, _ := CheckService(rc, "osqueryd")
		return status == ServiceStatusActive
	}
	return false
}

// AddBootstrapFlags adds all bootstrap flags to a command
func AddBootstrapFlags(cmd *cobra.Command) {
	// Cluster flags
	cmd.Flags().String("join-cluster", "", "Join existing cluster at specified master address")
	cmd.Flags().Bool("single-node", false, "Explicitly configure as single-node deployment")
	cmd.Flags().String("preferred-role", "", "Preferred role when joining cluster (edge/core/data/compute)")
	cmd.Flags().Bool("auto-discover", false, "Enable automatic cluster discovery via multicast")
	
	// Feature flags
	cmd.Flags().Bool("skip-hardening", false, "Skip Ubuntu security hardening")
	cmd.Flags().Bool("skip-storage", false, "Skip storage operations deployment")
	cmd.Flags().Bool("skip-tailscale", false, "Skip Tailscale installation")
	cmd.Flags().Bool("skip-osquery", false, "Skip OSQuery installation")
	
	// Advanced flags
	cmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	cmd.Flags().Bool("validate-only", false, "Only validate system requirements")
	cmd.Flags().Bool("force", false, "Force bootstrap even if already completed")
}