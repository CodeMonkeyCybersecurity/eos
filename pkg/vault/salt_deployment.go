package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

// OrchestrateVaultEnableViaSalt enables Vault features using Salt states
// This replaces EnableVault() when Salt is available
func OrchestrateVaultEnableViaSalt(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault enablement via Salt states")

	// ASSESS - Check prerequisites
	if err := checkSaltAvailability(rc); err != nil {
		logger.Error("Salt not available for enablement", zap.Error(err))
		return fmt.Errorf("Salt not available: %w", err)
	}

	// Check if Vault is initialized and unsealed
	if err := checkVaultReadyForEnablement(rc); err != nil {
		return fmt.Errorf("Vault not ready for enablement: %w", err)
	}

	// INTERVENE - Apply enablement via Salt
	logger.Info("Applying Vault enablement Salt states")
	
	saltClient := saltstack.NewClient(logger)
	ctx, cancel := context.WithTimeout(rc.Ctx, 300*time.Second) // 5 minutes
	defer cancel()

	// Get root token from init file
	rootToken, err := getRootTokenFromInitFile(rc)
	if err != nil {
		return fmt.Errorf("failed to get root token: %w", err)
	}

	// Prepare pillar data
	pillarData := map[string]interface{}{
		"vault": map[string]interface{}{
			"root_token":      rootToken,
			"enable_userpass": true,
			"enable_approle":  true,
			"enable_mfa":      true,
			"enable_agent":    true,
		},
	}

	// Apply enablement state
	if err := saltClient.StateApplyLocal(ctx, "hashicorp.vault.enable", pillarData); err != nil {
		return fmt.Errorf("failed to apply enablement Salt states: %w", err)
	}

	// EVALUATE - Verify enablement
	logger.Info("Verifying Vault enablement")
	
	if err := verifyVaultEnablement(rc); err != nil {
		return fmt.Errorf("Vault enablement verification failed: %w", err)
	}

	logger.Info("Vault enablement via Salt completed successfully")
	return nil
}

// OrchestrateVaultHardenViaSalt applies comprehensive hardening using Salt states
func OrchestrateVaultHardenViaSalt(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault hardening via Salt states")

	// ASSESS
	if err := checkSaltAvailability(rc); err != nil {
		logger.Error("Salt not available for hardening", zap.Error(err))
		return fmt.Errorf("Salt not available: %w", err)
	}

	// INTERVENE
	logger.Info("Applying Vault hardening Salt states")
	
	saltClient := saltstack.NewClient(logger)
	ctx, cancel := context.WithTimeout(rc.Ctx, 600*time.Second) // 10 minutes
	defer cancel()

	// Get root token if available
	rootToken, _ := getRootTokenFromInitFile(rc)

	// Prepare pillar data
	pillarData := map[string]interface{}{
		"vault": map[string]interface{}{
			"root_token":      rootToken,
			"allowed_subnets": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
	}

	// Apply hardening state
	if err := saltClient.StateApplyLocal(ctx, "hashicorp.vault.harden", pillarData); err != nil {
		return fmt.Errorf("failed to apply hardening Salt states: %w", err)
	}

	// EVALUATE
	logger.Info("Verifying Vault hardening")
	
	if err := verifyVaultHardening(rc); err != nil {
		logger.Warn("Some hardening checks failed", zap.Error(err))
		// Don't fail completely - hardening is best-effort
	}

	logger.Info("Vault hardening via Salt completed")
	return nil
}

// OrchestrateVaultCompleteLifecycle runs the entire Vault lifecycle via Salt
func OrchestrateVaultCompleteLifecycle(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting complete Vault lifecycle via Salt orchestration")

	// Check Salt availability once
	if err := checkSaltAvailability(rc); err != nil {
		logger.Error("Salt not available for complete lifecycle", zap.Error(err))
		return fmt.Errorf("Salt not available: %w", err)
	}

	saltClient := saltstack.NewClient(logger)
	ctx, cancel := context.WithTimeout(rc.Ctx, 1200*time.Second) // 20 minutes total
	defer cancel()

	// Prepare comprehensive pillar data
	pillarData := map[string]interface{}{
		"vault": map[string]interface{}{
			"enable_userpass":  true,
			"enable_approle":   true,
			"enable_mfa":       true,
			"enable_agent":     true,
			"allowed_subnets":  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
	}

	// Apply complete lifecycle orchestration
	logger.Info("Applying complete Vault lifecycle Salt orchestration")
	if err := saltClient.StateApplyLocal(ctx, "hashicorp.vault.complete_lifecycle", pillarData); err != nil {
		return fmt.Errorf("failed to apply complete lifecycle: %w", err)
	}

	logger.Info("Complete Vault lifecycle deployment successful")
	return nil
}

// Helper functions

func checkVaultReadyForEnablement(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Set environment variables for Vault
	os.Setenv("VAULT_ADDR", "https://127.0.0.1:8179")
	os.Setenv("VAULT_SKIP_VERIFY", "true")
	defer func() {
		os.Unsetenv("VAULT_ADDR")
		os.Unsetenv("VAULT_SKIP_VERIFY")
	}()
	
	// Check if Vault is initialized
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"status", "-format=json"},
		Capture: true,
	})

	if err != nil {
		// vault status returns non-zero when sealed, so parse output anyway
		if output == "" {
			return fmt.Errorf("Vault not responding")
		}
	}

	// Parse status
	var status struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}

	if err := json.Unmarshal([]byte(output), &status); err != nil {
		return fmt.Errorf("failed to parse Vault status: %w", err)
	}

	if !status.Initialized {
		return fmt.Errorf("Vault is not initialized")
	}

	if status.Sealed {
		logger.Info("Vault is sealed, attempting to unseal via Salt")
		// Try to unseal via Salt
		saltClient := saltstack.NewClient(logger)
		if err := saltClient.StateApplyLocal(rc.Ctx, "hashicorp.vault.unseal", nil); err != nil {
			return fmt.Errorf("failed to unseal Vault: %w", err)
		}
	}

	return nil
}

func getRootTokenFromInitFile(rc *eos_io.RuntimeContext) (string, error) {
	initFile := "/var/lib/eos/secret/vault_init.json"
	
	data, err := os.ReadFile(initFile)
	if err != nil {
		return "", fmt.Errorf("failed to read init file: %w", err)
	}

	var initData struct {
		RootToken string `json:"root_token"`
	}

	if err := json.Unmarshal(data, &initData); err != nil {
		return "", fmt.Errorf("failed to parse init file: %w", err)
	}

	if initData.RootToken == "" {
		return "", fmt.Errorf("root token not found in init file")
	}

	return initData.RootToken, nil
}

func verifyVaultEnablement(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check auth methods
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"auth", "list", "-format=json"},
		Capture: true,
	})

	if err != nil {
		logger.Warn("Failed to list auth methods", zap.Error(err))
	}

	// Check audit devices
	auditOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"audit", "list"},
		Capture: true,
	})

	if err != nil || !strings.Contains(auditOutput, "file/") {
		return fmt.Errorf("audit logging not properly configured")
	}

	logger.Info("Vault enablement verified",
		zap.String("auth_methods", output))

	return nil
}

func verifyVaultHardening(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if swap is disabled
	swapOutput, _ := execute.Run(rc.Ctx, execute.Options{
		Command: "swapon",
		Args:    []string{"--show"},
		Capture: true,
	})

	if swapOutput != "" {
		logger.Warn("Swap is still enabled")
	}

	// Check firewall status
	ufwOutput, _ := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status"},
		Capture: true,
	})

	if !strings.Contains(ufwOutput, "Status: active") {
		logger.Warn("Firewall not active")
	}

	// Check backup configuration
	if _, err := os.Stat("/usr/local/bin/vault-backup.sh"); err != nil {
		logger.Warn("Backup script not found")
	}

	logger.Info("Vault hardening verification completed")
	return nil
}