// pkg/vault/agent_lifecycle.go

package vault

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultAgentConfig represents configuration options for Vault Agent
type VaultAgentConfig struct {
	EnableCache      bool   `json:"enable_cache"`
	ListenerAddress  string `json:"listener_address"`
	EnableAutoAuth   bool   `json:"enable_auto_auth"`
	CacheTemplates   bool   `json:"cache_templates"`
	LogLevel         string `json:"log_level"`
	MaxRetries       int    `json:"max_retries"`
	RetryDelay       string `json:"retry_delay"`
}

// DefaultVaultAgentConfig returns secure defaults for Vault Agent
func DefaultVaultAgentConfig() *VaultAgentConfig {
	return &VaultAgentConfig{
		EnableCache:     true,
		ListenerAddress: "127.0.0.1:8100",
		EnableAutoAuth:  true,
		CacheTemplates:  true,
		LogLevel:        "info",
		MaxRetries:      3,
		RetryDelay:      "5s",
	}
}

// PhaseEnableVaultAgent provides comprehensive Vault Agent setup
func PhaseEnableVaultAgent(rc *eos_io.RuntimeContext, client *api.Client, config *VaultAgentConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🤖 Starting comprehensive Vault Agent enablement")

	if config == nil {
		config = DefaultVaultAgentConfig()
	}

	// Step 1: Verify prerequisites
	if err := verifyAgentPrerequisites(rc, client); err != nil {
		return fmt.Errorf("agent prerequisites check failed: %w", err)
	}

	// Step 2: Ensure AppRole credentials exist
	if err := ensureAppRoleCredentials(rc, client); err != nil {
		return fmt.Errorf("AppRole credentials setup failed: %w", err)
	}

	// Step 3: Configure Vault Agent
	if err := PhaseRenderVaultAgentConfig(rc, client); err != nil {
		return fmt.Errorf("agent configuration failed: %w", err)
	}

	// Step 4: Start and validate Vault Agent
	if err := PhaseStartVaultAgentAndValidate(rc, client); err != nil {
		return fmt.Errorf("agent start and validation failed: %w", err)
	}

	// Step 5: Verify agent functionality
	if err := verifyAgentFunctionality(rc, client); err != nil {
		return fmt.Errorf("agent functionality verification failed: %w", err)
	}

	// Step 6: Configure agent monitoring
	if err := configureAgentMonitoring(rc, config); err != nil {
		log.Warn("⚠️ Agent monitoring setup failed", zap.Error(err))
	}

	log.Info("✅ Vault Agent enablement completed successfully")
	return nil
}

// verifyAgentPrerequisites checks that all required components are ready
func verifyAgentPrerequisites(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔍 Verifying Vault Agent prerequisites")

	// Check Vault is accessible
	if IsVaultSealed(client) {
		return fmt.Errorf("Vault is sealed - cannot configure agent")
	}

	// Verify Vault is healthy
	health, err := client.Sys().Health()
	if err != nil {
		return fmt.Errorf("failed to check Vault health: %w", err)
	}
	if !health.Initialized {
		return fmt.Errorf("Vault is not initialized")
	}

	// Check AppRole auth method is enabled
	authMethods, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("failed to list auth methods: %w", err)
	}

	approleFound := false
	for path, method := range authMethods {
		if method.Type == "approle" {
			approleFound = true
			log.Info("✅ AppRole auth method found", zap.String("path", path))
			break
		}
	}

	if !approleFound {
		return fmt.Errorf("AppRole auth method is required but not enabled")
	}

	// Verify eos user exists
	if _, _, err := eos_unix.LookupUser(rc.Ctx, shared.EosID); err != nil {
		return fmt.Errorf("eos system user not found: %w", err)
	}

	log.Info("✅ All prerequisites verified")
	return nil
}

// ensureAppRoleCredentials ensures AppRole credentials are available
func ensureAppRoleCredentials(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔑 Ensuring AppRole credentials are available")

	// Check if credentials already exist on disk
	if credentialsExistOnDisk() {
		log.Info("✅ AppRole credentials found on disk")
		return nil
	}

	// Try to retrieve from Vault
	roleID, secretID, err := getAppRoleCredentialsFromVault(rc, client)
	if err != nil {
		return fmt.Errorf("failed to get AppRole credentials: %w", err)
	}

	// Write credentials to disk
	if err := writeAppRoleCredentialsToDisk(rc, roleID, secretID); err != nil {
		return fmt.Errorf("failed to write AppRole credentials: %w", err)
	}

	log.Info("✅ AppRole credentials configured")
	return nil
}

// credentialsExistOnDisk checks if AppRole credentials exist on disk
func credentialsExistOnDisk() bool {
	_, err1 := os.Stat(shared.AppRolePaths.RoleID)
	_, err2 := os.Stat(shared.AppRolePaths.SecretID)
	return err1 == nil && err2 == nil
}

// getAppRoleCredentialsFromVault retrieves credentials from Vault
func getAppRoleCredentialsFromVault(rc *eos_io.RuntimeContext, client *api.Client) (string, string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Get role ID
	roleIDPath := fmt.Sprintf("auth/approle/role/%s/role-id", shared.AppRoleName)
	roleIDResp, err := client.Logical().Read(roleIDPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read role ID: %w", err)
	}
	if roleIDResp == nil || roleIDResp.Data["role_id"] == nil {
		return "", "", fmt.Errorf("role ID not found in response")
	}
	roleID := roleIDResp.Data["role_id"].(string)

	// Generate new secret ID
	secretIDPath := fmt.Sprintf("auth/approle/role/%s/secret-id", shared.AppRoleName)
	secretIDResp, err := client.Logical().Write(secretIDPath, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate secret ID: %w", err)
	}
	if secretIDResp == nil || secretIDResp.Data["secret_id"] == nil {
		return "", "", fmt.Errorf("secret ID not found in response")
	}
	secretID := secretIDResp.Data["secret_id"].(string)

	log.Info("✅ AppRole credentials retrieved from Vault")
	return roleID, secretID, nil
}

// writeAppRoleCredentialsToDisk writes credentials to secure files
func writeAppRoleCredentialsToDisk(rc *eos_io.RuntimeContext, roleID, secretID string) error {
	log := otelzap.Ctx(rc.Ctx)

	// Ensure secrets directory exists
	if err := shared.EnsureSecretsDir(); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}

	// Write role ID
	if err := os.WriteFile(shared.AppRolePaths.RoleID, []byte(roleID), shared.OwnerReadOnly); err != nil {
		return fmt.Errorf("failed to write role ID: %w", err)
	}

	// Write secret ID
	if err := os.WriteFile(shared.AppRolePaths.SecretID, []byte(secretID), shared.OwnerReadOnly); err != nil {
		return fmt.Errorf("failed to write secret ID: %w", err)
	}

	// Set proper ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, shared.EosID)
	if err != nil {
		return fmt.Errorf("failed to lookup eos user: %w", err)
	}

	if err := os.Chown(shared.AppRolePaths.RoleID, uid, gid); err != nil {
		log.Warn("⚠️ Failed to set role ID file ownership", zap.Error(err))
	}
	if err := os.Chown(shared.AppRolePaths.SecretID, uid, gid); err != nil {
		log.Warn("⚠️ Failed to set secret ID file ownership", zap.Error(err))
	}

	log.Info("✅ AppRole credentials written to disk")
	return nil
}

// verifyAgentFunctionality tests that the agent is working correctly
func verifyAgentFunctionality(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🧪 Verifying Vault Agent functionality")

	// Wait for agent to be fully ready
	time.Sleep(2 * time.Second)

	// Check if agent token file exists and is readable
	tokenPath := shared.AgentToken
	if _, err := os.Stat(tokenPath); err != nil {
		return fmt.Errorf("agent token file not found: %w", err)
	}

	// Read the token
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("failed to read agent token: %w", err)
	}
	if len(tokenData) == 0 {
		return fmt.Errorf("agent token file is empty")
	}

	// Test token validity by making a simple API call
	agentClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}
	
	agentClient.SetToken(string(tokenData))
	agentClient.SetAddress(client.Address())

	// Simple test - lookup self
	_, err = agentClient.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("agent token validation failed: %w", err)
	}

	// Check agent service status
	if err := checkAgentServiceStatus(rc); err != nil {
		return fmt.Errorf("agent service check failed: %w", err)
	}

	log.Info("✅ Vault Agent functionality verified")
	return nil
}

// checkAgentServiceStatus verifies the agent service is running
func checkAgentServiceStatus(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check if service is active
	if err := eos_unix.CheckServiceStatus(rc.Ctx, shared.VaultAgentService); err != nil {
		return fmt.Errorf("agent service not running: %w", err)
	}

	log.Info("✅ Vault Agent service is running")
	return nil
}

// configureAgentMonitoring sets up monitoring and health checks for the agent
func configureAgentMonitoring(rc *eos_io.RuntimeContext, config *VaultAgentConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("📊 Configuring Vault Agent monitoring")

	// Create agent health check script
	healthCheckScript := `#!/bin/bash
# Vault Agent health check script
set -euo pipefail

TOKEN_FILE="` + shared.AgentToken + `"
SERVICE_NAME="` + shared.VaultAgentService + `"
MAX_AGE=300  # 5 minutes

# Check if service is running
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "CRITICAL: $SERVICE_NAME is not running"
    exit 2
fi

# Check if token file exists and is recent
if [[ ! -f "$TOKEN_FILE" ]]; then
    echo "CRITICAL: Token file not found at $TOKEN_FILE"
    exit 2
fi

# Check token file age
if [[ $(($(date +%s) - $(stat -c %Y "$TOKEN_FILE"))) -gt $MAX_AGE ]]; then
    echo "WARNING: Token file is older than $MAX_AGE seconds"
    exit 1
fi

# Check token file is not empty
if [[ ! -s "$TOKEN_FILE" ]]; then
    echo "CRITICAL: Token file is empty"
    exit 2
fi

echo "OK: Vault Agent is healthy"
exit 0
`

	healthCheckPath := "/usr/local/bin/vault-agent-health-check.sh"
	if err := os.WriteFile(healthCheckPath, []byte(healthCheckScript), 0755); err != nil {
		return fmt.Errorf("failed to write health check script: %w", err)
	}

	// Create systemd timer for monitoring
	timerContent := `[Unit]
Description=Vault Agent Health Check Timer
Requires=vault-agent-health-check.service

[Timer]
OnCalendar=*:0/5  # Every 5 minutes
Persistent=true

[Install]
WantedBy=timers.target
`

	serviceContent := `[Unit]
Description=Vault Agent Health Check Service
After=` + shared.VaultAgentService + `

[Service]
Type=oneshot
ExecStart=` + healthCheckPath + `
User=eos
Group=eos
`

	// Write timer and service files
	timerPath := "/etc/systemd/system/vault-agent-health-check.timer"
	servicePath := "/etc/systemd/system/vault-agent-health-check.service"

	if err := os.WriteFile(timerPath, []byte(timerContent), 0644); err != nil {
		return fmt.Errorf("failed to write health check timer: %w", err)
	}

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write health check service: %w", err)
	}

	// Enable the health check timer
	if err := eos_unix.ReloadDaemonAndEnable(rc.Ctx, "vault-agent-health-check.timer"); err != nil {
		log.Warn("⚠️ Failed to enable health check timer", zap.Error(err))
	}

	log.Info("✅ Vault Agent monitoring configured")
	return nil
}

// AgentStatus represents the current status of Vault Agent
type AgentStatus struct {
	ServiceRunning bool      `json:"service_running"`
	TokenAvailable bool      `json:"token_available"`
	TokenValid     bool      `json:"token_valid"`
	LastTokenTime  time.Time `json:"last_token_time"`
	ConfigValid    bool      `json:"config_valid"`
	HealthStatus   string    `json:"health_status"`
}

// GetAgentStatus returns comprehensive status information about Vault Agent
func GetAgentStatus(rc *eos_io.RuntimeContext) (*AgentStatus, error) {
	log := otelzap.Ctx(rc.Ctx)
	status := &AgentStatus{}

	// Check service status
	err := eos_unix.CheckServiceStatus(rc.Ctx, shared.VaultAgentService)
	status.ServiceRunning = err == nil

	// Check token file
	tokenPath := shared.AgentToken
	if stat, err := os.Stat(tokenPath); err == nil {
		status.TokenAvailable = true
		status.LastTokenTime = stat.ModTime()

		// Check if token is valid by reading it
		if tokenData, err := os.ReadFile(tokenPath); err == nil && len(tokenData) > 0 {
			status.TokenValid = true
		}
	}

	// Check config file
	if _, err := os.Stat(shared.VaultAgentConfigPath); err == nil {
		status.ConfigValid = true
	}

	// Determine overall health status
	if status.ServiceRunning && status.TokenAvailable && status.TokenValid && status.ConfigValid {
		status.HealthStatus = "healthy"
	} else if status.ServiceRunning {
		status.HealthStatus = "degraded"
	} else {
		status.HealthStatus = "unhealthy"
	}

	log.Debug("Agent status checked", 
		zap.Bool("service_running", status.ServiceRunning),
		zap.Bool("token_available", status.TokenAvailable),
		zap.Bool("token_valid", status.TokenValid),
		zap.String("health", status.HealthStatus))

	return status, nil
}