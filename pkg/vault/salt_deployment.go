package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// OrchestrateVaultCreateViaNomad creates a complete Vault deployment using Nomad orchestration
// This replaces Salt-based deployment for HashiCorp stack consistency
// Following the principle: Nomad = Service orchestration
func OrchestrateVaultCreateViaNomad(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	logger.Info("Starting complete Vault deployment via Nomad orchestration")

	// ASSESS - Check prerequisites
	logger.Info("Assessing Vault deployment prerequisites")
	
	// Check if Nomad is available
	if err := checkNomadAvailability(rc); err != nil {
		logger.Error("Nomad not available, falling back to direct deployment", zap.Error(err))
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

	logger.Info("Nomad-based Vault deployment completed successfully")
	return nil
}


// assessExistingVault checks for existing Vault installation
func assessExistingVault(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	
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
	// TODO: Replace with Nomad job deployment
	return fmt.Errorf("Nomad-based Vault deployment not yet implemented")
}

// verifyVaultDeployment verifies that the Salt-based Vault deployment succeeded
func verifyVaultDeployment(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	
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
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	
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
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	
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
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	logger.Info("Starting Vault enablement via Salt states")

	// ASSESS - Check prerequisites
	if err := checkNomadAvailability(rc); err != nil {
		logger.Error("Salt not available for enablement", zap.Error(err))
		return fmt.Errorf("Salt not available: %w", err)
	}

	// Check if Vault is initialized and unsealed
	if err := checkVaultReadyForEnablement(rc); err != nil {
		return fmt.Errorf("Vault not ready for enablement: %w", err)
	}

	// TODO: Replace with Nomad job deployment
	return fmt.Errorf("Nomad-based Vault enablement not yet implemented")
}

// OrchestrateVaultHardenViaSalt applies comprehensive hardening using Salt states
func OrchestrateVaultHardenViaSalt(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	logger.Info("Starting Vault hardening via Salt states")

	// ASSESS
	if err := checkNomadAvailability(rc); err != nil {
		logger.Error("Salt not available for hardening", zap.Error(err))
		return fmt.Errorf("Salt not available: %w", err)
	}

	// TODO: Replace with Nomad job deployment
	return fmt.Errorf("Nomad-based Vault hardening not yet implemented")
}

// OrchestrateVaultCompleteLifecycle runs the entire Vault lifecycle via Salt
func OrchestrateVaultCompleteLifecycle(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	logger.Info("Starting complete Vault lifecycle via Salt orchestration")

	// Check Salt availability once
	if err := checkNomadAvailability(rc); err != nil {
		logger.Error("Salt not available for complete lifecycle", zap.Error(err))
		return fmt.Errorf("Salt not available: %w", err)
	}

	// TODO: Replace with Nomad job deployment
	return fmt.Errorf("Nomad-based Vault complete lifecycle not yet implemented")
}

func checkVaultReadyForEnablement(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	
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
		// TODO: Replace with Nomad job deployment
		return fmt.Errorf("Nomad-based Vault unseal not yet implemented")
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
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	
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
	logger := zap.L().With(zap.String("component", "vault_deployment"))
	
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