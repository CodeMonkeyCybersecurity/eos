package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OrchestrateVaultCreateViaSalt creates a complete Vault deployment using Salt states
// This replaces OrchestrateVaultCreate() for architectural consistency
// Following the principle: Salt = Physical infrastructure
func OrchestrateVaultCreateViaSalt(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting complete Vault deployment via Salt states")

	// ASSESS - Check prerequisites
	logger.Info("Assessing Vault deployment prerequisites")
	
	// Check if Salt is available
	if err := checkSaltAvailability(rc); err != nil {
		logger.Error("Salt not available, falling back to direct deployment", zap.Error(err))
		return OrchestrateVaultCreate(rc)
	}

	// Check for existing Vault installation
	if err := assessExistingVault(rc); err != nil {
		logger.Warn("Existing Vault installation detected", zap.Error(err))
		// Continue anyway - Salt states are idempotent
	}

	// INTERVENE - Deploy via comprehensive Salt orchestration
	logger.Info("Deploying Vault via comprehensive Salt states")
	
	if err := deploySaltVaultComplete(rc); err != nil {
		logger.Error("Salt-based Vault deployment failed, attempting fallback", zap.Error(err))
		return OrchestrateVaultCreate(rc)
	}

	// EVALUATE - Verify deployment
	logger.Info("Verifying Salt-based Vault deployment")
	
	if err := verifyVaultDeployment(rc); err != nil {
		logger.Error("Vault deployment verification failed", zap.Error(err))
		return fmt.Errorf("Vault deployment verification failed: %w", err)
	}

	logger.Info("Salt-based Vault deployment completed successfully")
	return nil
}

// checkSaltAvailability checks if Salt is available for Vault deployment
func checkSaltAvailability(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if salt-call is available
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-call"},
		Capture: true,
		Timeout: 10 * time.Second,
	}); err != nil {
		logger.Warn("salt-call not found in PATH", zap.Error(err))
		return fmt.Errorf("salt-call not available: %w", err)
	}
	
	// Check if Vault Salt states exist
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "test",
		Args:    []string{"-f", "/opt/eos/salt/states/hashicorp/vault/eos_complete.sls"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err != nil {
		logger.Warn("Vault Salt states not found", zap.Error(err))
		return fmt.Errorf("Vault Salt states not available")
	}
	
	logger.Info("Salt availability verified for Vault deployment")
	return nil
}

// assessExistingVault checks for existing Vault installation
func assessExistingVault(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Vault binary exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"vault"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		logger.Info("Existing Vault binary detected")
		
		// Check if Vault service is running
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", "vault"},
			Capture: true,
			Timeout: 5 * time.Second,
		}); err == nil {
			return fmt.Errorf("Vault service is already running")
		}
	}
	
	return nil
}

// deploySaltVaultComplete applies the complete Vault Salt orchestration
func deploySaltVaultComplete(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Salt client
	saltClient := saltstack.NewClient(logger)
	
	// Create context with extended timeout for complete deployment
	ctx, cancel := context.WithTimeout(rc.Ctx, 600*time.Second) // 10 minutes
	defer cancel()
	
	// Prepare pillar data for Vault deployment
	pillarData := map[string]interface{}{
		"vault": map[string]interface{}{
			"user":        "vault",
			"group":       "vault",
			"port":        "8179",  // Eos-specific port
			"log_level":   "info",
			"log_format":  "json",
			"tls_enabled": true,
			"ui_enabled":  true,
		},
	}
	
	logger.Info("Applying complete Vault Salt orchestration")
	
	// Apply the comprehensive Vault state
	if err := saltClient.StateApplyLocal(ctx, "hashicorp.vault.eos_complete", pillarData); err != nil {
		logger.Error("Failed to apply Vault Salt states", zap.Error(err))
		return fmt.Errorf("failed to apply Vault Salt states: %w", err)
	}
	
	logger.Info("Vault Salt states applied successfully")
	return nil
}

// verifyVaultDeployment verifies that the Salt-based Vault deployment succeeded
func verifyVaultDeployment(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Vault binary is installed
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"version"},
		Capture: true,
		Timeout: 10 * time.Second,
	}); err != nil {
		return fmt.Errorf("Vault binary not installed or not working: %w", err)
	}
	
	// Check if service is running
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "vault"},
		Capture: true,
		Timeout: 10 * time.Second,
	}); err != nil {
		return fmt.Errorf("Vault service is not running: %w", err)
	}
	
	// Check if configuration files exist
	configFiles := []string{
		"/etc/vault.d/vault.hcl",
		"/etc/vault.d/ca.crt",
		"/opt/vault/tls/tls.crt",
		"/opt/vault/tls/tls.key",
	}
	
	for _, file := range configFiles {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "test",
			Args:    []string{"-f", file},
			Capture: true,
			Timeout: 5 * time.Second,
		}); err != nil {
			return fmt.Errorf("required configuration file missing: %s", file)
		}
	}
	
	// Test TCP connectivity to Vault (replicating health check from Go code)
	if err := testVaultConnectivity(rc); err != nil {
		return fmt.Errorf("Vault connectivity test failed: %w", err)
	}
	
	// Check if initialization file exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "test",
		Args:    []string{"-f", "/var/lib/eos/secret/vault_init.json"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err != nil {
		logger.Warn("Vault initialization file not found - may need manual initialization")
	} else {
		logger.Info("Vault initialization file found - Vault appears to be fully configured")
	}
	
	logger.Info("Vault deployment verification completed successfully")
	return nil
}

// testVaultConnectivity tests TCP connectivity to Vault
func testVaultConnectivity(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test TCP connectivity with timeout (replicating exact logic from phase5_start_service.go)
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "timeout",
		Args:    []string{"3", "bash", "-c", "</dev/tcp/127.0.0.1/8179"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	
	if err != nil {
		// Get service logs for debugging
		logs, _ := execute.Run(rc.Ctx, execute.Options{
			Command: "journalctl",
			Args:    []string{"-u", "vault", "-n", "20", "--no-pager"},
			Capture: true,
			Timeout: 10 * time.Second,
		})
		
		logger.Error("Vault TCP connectivity test failed",
			zap.Error(err),
			zap.String("output", output),
			zap.String("service_logs", logs))
		
		return fmt.Errorf("Vault not responding on port 8179: %w", err)
	}
	
	logger.Info("Vault TCP connectivity test passed")
	return nil
}

// GetVaultStatusViaSalt gets Vault status using Salt-compatible methods
func GetVaultStatusViaSalt(rc *eos_io.RuntimeContext) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	status := make(map[string]interface{})
	
	// Check if binary exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"vault"},
		Capture: true,
	}); err != nil {
		status["binary_installed"] = false
	} else {
		status["binary_installed"] = true
	}
	
	// Check service status
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "vault"},
		Capture: true,
	}); err != nil {
		status["service_active"] = false
	} else {
		status["service_active"] = strings.TrimSpace(output) == "active"
	}
	
	// Check if initialization file exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "test",
		Args:    []string{"-f", "/var/lib/eos/secret/vault_init.json"},
		Capture: true,
	}); err != nil {
		status["initialized"] = false
	} else {
		status["initialized"] = true
	}
	
	// Get version if available
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"version"},
		Capture: true,
	}); err == nil {
		status["version"] = strings.TrimSpace(output)
	}
	
	logger.Info("Vault status check completed",
		zap.Any("status", status))
	
	return status, nil
}