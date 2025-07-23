// Example migration of consul command to use unified Salt client
// This shows how to replace the current inconsistent Salt patterns with the unified client

package create

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/unified"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Example of what the consul command would look like with unified client
var CreateConsulUnifiedCmd = &cobra.Command{
	Use:   "consul-unified",
	Short: "Install and configure HashiCorp Consul using unified Salt client (EXAMPLE)",
	Long: `EXAMPLE: Install and configure HashiCorp Consul using the unified Salt client.

This is an example showing how the consul command would be migrated to use the
new unified Salt client interface, eliminating all the inconsistent Salt API
detection and usage patterns currently in the codebase.

Key improvements:
• Consistent Salt API detection across all commands
• Unified error handling and retry logic  
• Automatic fallback from API to local mode
• Centralized configuration management
• Idempotent operations
• Better logging and debugging`,
	RunE: eos_cli.Wrap(runCreateConsulUnified),
}

func runCreateConsulUnified(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}
	
	logger.Info("Starting Consul installation using unified Salt client")
	
	// STEP 1: Create unified Salt client optimized for state operations
	// This replaces all the inconsistent Salt detection logic
	saltClient, err := unified.GetSaltClientForState(rc.Ctx, true) // Prefer API mode
	if err != nil {
		return fmt.Errorf("failed to create Salt client: %w", err)
	}
	defer saltClient.Close()
	
	// STEP 2: Get client status and show user what mode we're using
	// This provides clear visibility into Salt availability
	status, err := saltClient.GetStatus(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get Salt status: %w", err)
	}
	
	logger.Info("Salt client status",
		zap.String("mode", status.CurrentMode.String()),
		zap.Bool("healthy", status.Healthy),
		zap.Bool("api_available", status.Availability.APIConnectable))
	
	// Log any issues for debugging
	if len(status.Availability.Issues) > 0 {
		logger.Info("Salt availability issues detected",
			zap.Strings("issues", status.Availability.Issues))
	}
	
	// STEP 3: Verify Salt is working with a simple ping
	// This replaces the various different Salt verification patterns
	if !status.Healthy {
		logger.Info("Salt not healthy, performing diagnostic ping")
		
		pingOK, err := saltClient.Ping(rc.Ctx, "local")
		if err != nil || !pingOK {
			return eos_err.NewUserError("Salt is not working properly. Please run 'eos create saltstack' first.")
		}
	}
	
	// STEP 4: Check if Consul is already installed (idempotency)
	// This uses consistent service checking across all commands
	consulStatus, err := saltClient.CheckServiceStatus(rc.Ctx, "local", "consul")
	if err == nil {
		if running := consulStatus["running"].(bool); running {
			// Get flags to check if force reinstall requested
			forceReinstall, _ := cmd.Flags().GetBool("force")
			cleanInstall, _ := cmd.Flags().GetBool("clean")
			
			if !forceReinstall && !cleanInstall {
				logger.Info("terminal prompt: Consul is already installed and running.")
				logger.Info("terminal prompt: Use --force to reconfigure or --clean for a fresh install.")
				return nil
			}
		}
	}
	
	// STEP 5: Prepare pillar data
	// This uses the same pillar structure but with cleaner flag handling
	datacenterName, _ := cmd.Flags().GetString("datacenter")
	disableVaultIntegration, _ := cmd.Flags().GetBool("no-vault-integration")
	enableDebugLogging, _ := cmd.Flags().GetBool("debug")
	forceReinstall, _ := cmd.Flags().GetBool("force")
	cleanInstall, _ := cmd.Flags().GetBool("clean")
	
	pillar := map[string]interface{}{
		"consul": map[string]interface{}{
			"datacenter":        datacenterName,
			"bootstrap_expect":  1,
			"server_mode":       true,
			"vault_integration": !disableVaultIntegration,
			"log_level":         getLogLevelUnified(enableDebugLogging),
			"force_install":     forceReinstall,
			"clean_install":     cleanInstall,
			"bind_addr":         "0.0.0.0",
			"client_addr":       "0.0.0.0",
			"ui_enabled":        true,
			"connect_enabled":   true,
			"dns_port":          8600,
			"http_port":         shared.PortConsul,
			"grpc_port":         8502,
		},
	}
	
	// STEP 6: Apply Salt state with progress tracking
	// This provides consistent state application across all commands
	logger.Info("terminal prompt: Applying Consul Salt state...")
	
	stateResult, err := saltClient.ApplyState(rc.Ctx, "local", "hashicorp.consul", pillar)
	if err != nil {
		return fmt.Errorf("failed to apply Consul state: %w", err)
	}
	
	// STEP 7: Handle state results consistently
	if !stateResult.Success {
		logger.Error("Consul state application failed",
			zap.Strings("errors", stateResult.Errors))
		
		logger.Info("terminal prompt: ❌ Consul installation failed:")
		for _, err := range stateResult.Errors {
			logger.Info(fmt.Sprintf("terminal prompt:   - %s", err))
		}
		
		return fmt.Errorf("consul installation failed")
	}
	
	// Log state summary
	logger.Info("Consul state applied successfully",
		zap.String("mode", stateResult.Mode.String()),
		zap.Int("total_states", stateResult.Summary.Total),
		zap.Int("succeeded", stateResult.Summary.Succeeded),
		zap.Int("failed", stateResult.Summary.Failed),
		zap.Int("changed", stateResult.Summary.Changed),
		zap.Duration("duration", stateResult.Duration))
	
	// STEP 8: Verify installation
	// This uses consistent verification across all commands
	logger.Info("Verifying Consul installation")
	
	// Wait a moment for service to start
	time.Sleep(5 * time.Second)
	
	// Check service status
	finalStatus, err := saltClient.CheckServiceStatus(rc.Ctx, "local", "consul")
	if err != nil {
		logger.Warn("Could not verify Consul service status", zap.Error(err))
	} else {
		if running := finalStatus["running"].(bool); !running {
			return fmt.Errorf("consul service is not running after installation")
		}
	}
	
	// Test basic functionality
	consulMembers, err := saltClient.RunShellCommand(rc.Ctx, "local", "consul members")
	if err != nil {
		logger.Warn("Could not verify Consul cluster", zap.Error(err))
	} else {
		logger.Debug("Consul cluster status", zap.String("members", consulMembers))
	}
	
	// STEP 9: Success message
	logger.Info("terminal prompt: ✅ Consul installation completed successfully!")
	logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", shared.PortConsul))
	logger.Info(fmt.Sprintf("terminal prompt: Used Salt %s mode", stateResult.Mode.String()))
	
	return nil
}

// Helper function (same as original)
func getLogLevelUnified(debug bool) string {
	if debug {
		return "DEBUG"
	}
	return "INFO"
}

func init() {
	// Add flags (same as original)
	CreateConsulUnifiedCmd.Flags().StringP("datacenter", "d", "dc1", "Datacenter name for Consul cluster")
	CreateConsulUnifiedCmd.Flags().Bool("no-vault-integration", false, "Disable automatic Vault integration")
	CreateConsulUnifiedCmd.Flags().Bool("debug", false, "Enable debug logging for Consul")
	CreateConsulUnifiedCmd.Flags().Bool("force", false, "Force reconfiguration even if Consul is running")
	CreateConsulUnifiedCmd.Flags().Bool("clean", false, "Remove all data and perform clean installation")
	
	// Register with create command
	CreateCmd.AddCommand(CreateConsulUnifiedCmd)
}

/*
COMPARISON: Old vs New Approach

OLD APPROACH (Current consul.go):
- Multiple initializeSaltClient() implementations across files
- Inconsistent error messages for same conditions
- Different Salt API detection patterns
- Manual fallback logic scattered everywhere
- Duplicate configuration loading
- Mixed context handling
- Different retry strategies

NEW APPROACH (This unified example):
- Single unified.GetSaltClientForState() call
- Consistent error messages and handling
- Unified Salt API detection and fallback
- Automatic mode selection and fallback
- Centralized configuration management
- Consistent context handling throughout
- Built-in retry logic with proper exponential backoff

BENEFITS:
1. Code Reduction: ~200 lines reduced to ~100 lines
2. Consistency: Same Salt behavior across all commands
3. Maintainability: One place to fix Salt issues
4. Reliability: Comprehensive error handling and retry logic
5. Observability: Better logging and status reporting
6. Testability: Easy to mock unified client interface

MIGRATION STEPS:
1. Replace initializeSaltClient() calls with unified.GetSaltClientForState()
2. Replace manual Salt API detection with client.GetStatus()
3. Replace custom fallback logic with unified client automatic fallback
4. Replace custom error handling with unified error types
5. Replace manual pillar/state execution with client.ApplyState()
6. Replace custom verification with client convenience methods
7. Update tests to use unified.MockClient interface
*/