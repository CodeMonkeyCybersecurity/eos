// pkg/vault/agent_lifecycle.go

package vault

import (
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultAgentConfig represents configuration options for Vault Agent
type VaultAgentConfig struct {
	EnableCache     bool   `json:"enable_cache"`
	ListenerAddress string `json:"listener_address"`
	EnableAutoAuth  bool   `json:"enable_auto_auth"`
	CacheTemplates  bool   `json:"cache_templates"`
	LogLevel        string `json:"log_level"`
	MaxRetries      int    `json:"max_retries"`
	RetryDelay      string `json:"retry_delay"`
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
	log.Info("📋 Verifying Vault Agent prerequisites")
	if err := verifyAgentPrerequisites(rc, client); err != nil {
		log.Error("❌ Agent prerequisites check failed", zap.Error(err))
		return cerr.Wrap(err, "agent prerequisites check failed")
	}

	// Step 2: Ensure AppRole credentials exist
	log.Info("🔑 Ensuring AppRole credentials exist")
	if err := ensureAppRoleCredentials(rc, client); err != nil {
		log.Error("❌ AppRole credentials setup failed", zap.Error(err))
		return cerr.Wrap(err, "AppRole credentials setup failed")
	}

	// Step 3: Configure Vault Agent
	log.Info("⚙️ Configuring Vault Agent")
	if err := PhaseRenderVaultAgentConfig(rc, client); err != nil {
		log.Error("❌ Agent configuration failed", zap.Error(err))
		return cerr.Wrap(err, "agent configuration failed")
	}

	// Step 4: Start and validate Vault Agent
	log.Info("🚀 Starting and validating Vault Agent")
	if err := PhaseStartVaultAgentAndValidate(rc, client); err != nil {
		log.Error("❌ Agent start and validation failed", zap.Error(err))
		return cerr.Wrap(err, "agent start and validation failed")
	}

	// Step 5: Verify agent functionality
	log.Info("🧪 Verifying agent functionality")
	if err := verifyAgentFunctionality(rc, client); err != nil {
		log.Error("❌ Agent functionality verification failed", zap.Error(err))
		return cerr.Wrap(err, "agent functionality verification failed")
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
		log.Error("❌ Vault is sealed - cannot configure agent")
		return cerr.New("Vault is sealed - cannot configure agent")
	}

	// Verify Vault is healthy
	log.Info("🏥 Checking Vault health status")
	health, err := client.Sys().Health()
	if err != nil {
		log.Error("❌ Failed to check Vault health", zap.Error(err))
		return cerr.Wrap(err, "failed to check Vault health")
	}
	if !health.Initialized {
		log.Error("❌ Vault is not initialized")
		return cerr.New("Vault is not initialized")
	}
	log.Info("✅ Vault is healthy",
		zap.Bool("initialized", health.Initialized),
		zap.Bool("sealed", health.Sealed),
		zap.String("version", health.Version))

	// Get privileged client with root token for auth method listing
	log.Info("🔑 Getting privileged client to check AppRole auth method")
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		log.Error("❌ Failed to get privileged Vault client for prerequisites check", zap.Error(err))
		return cerr.Wrap(err, "get privileged client for prerequisites")
	}

	// Log that we have a privileged client ready
	if privToken := privilegedClient.Token(); privToken != "" {
		log.Info("✅ Using privileged client for auth method verification")
	}

	// Check AppRole auth method is enabled
	log.Info("🔍 Checking for AppRole auth method")
	authMethods, err := privilegedClient.Sys().ListAuth()
	if err != nil {
		log.Error("❌ Failed to list auth methods", zap.Error(err))
		return cerr.Wrap(err, "failed to list auth methods")
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
		log.Error("❌ AppRole auth method is required but not enabled")
		return cerr.New("AppRole auth method is required but not enabled")
	}

	// Verify eos user exists
	log.Info("👤 Verifying eos system user exists")
	if _, _, err := eos_unix.LookupUser(rc.Ctx, shared.EosID); err != nil {
		log.Error("❌ eos system user not found",
			zap.String("user", shared.EosID),
			zap.Error(err))
		return cerr.Wrap(err, "eos system user not found")
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

	// Get privileged client with root token for AppRole operations
	log.Info("🔑 Getting privileged client for AppRole credential retrieval")
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		log.Error("❌ Failed to get privileged Vault client for AppRole credentials", zap.Error(err))
		return cerr.Wrap(err, "get privileged client for AppRole credentials")
	}

	// Log that we have a privileged client ready
	if privToken := privilegedClient.Token(); privToken != "" {
		log.Info("✅ Using privileged client for AppRole credential operations")
	}

	// Try to retrieve from Vault
	log.Info("📥 Retrieving AppRole credentials from Vault")
	roleID, secretID, err := getAppRoleCredentialsFromVault(rc, privilegedClient)
	if err != nil {
		log.Error("❌ Failed to get AppRole credentials from Vault", zap.Error(err))
		return cerr.Wrap(err, "failed to get AppRole credentials")
	}

	// Write credentials to disk
	log.Info("💾 Writing AppRole credentials to disk")
	if err := writeAppRoleCredentialsToDisk(rc, roleID, secretID); err != nil {
		log.Error("❌ Failed to write AppRole credentials", zap.Error(err))
		return cerr.Wrap(err, "failed to write AppRole credentials")
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
	roleIDPath := "auth/approle/role/" + shared.AppRoleName + "/role-id"
	log.Info("📞 Reading RoleID from Vault", zap.String("path", roleIDPath))
	roleIDResp, err := client.Logical().Read(roleIDPath)
	if err != nil {
		log.Error("❌ Failed to read role ID",
			zap.String("path", roleIDPath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "failed to read role ID")
	}
	if roleIDResp == nil || roleIDResp.Data["role_id"] == nil {
		log.Error("❌ Role ID not found in response",
			zap.Any("response", roleIDResp))
		return "", "", cerr.New("role ID not found in response")
	}
	roleID := roleIDResp.Data["role_id"].(string)
	log.Info("✅ RoleID retrieved")

	// Generate new secret ID
	secretIDPath := "auth/approle/role/" + shared.AppRoleName + "/secret-id"
	log.Info("📞 Generating new SecretID from Vault", zap.String("path", secretIDPath))
	secretIDResp, err := client.Logical().Write(secretIDPath, nil)
	if err != nil {
		log.Error("❌ Failed to generate secret ID",
			zap.String("path", secretIDPath),
			zap.Error(err))
		return "", "", cerr.Wrap(err, "failed to generate secret ID")
	}
	if secretIDResp == nil || secretIDResp.Data["secret_id"] == nil {
		log.Error("❌ Secret ID not found in response",
			zap.Any("response", secretIDResp))
		return "", "", cerr.New("secret ID not found in response")
	}
	secretID := secretIDResp.Data["secret_id"].(string)

	log.Info("✅ AppRole credentials retrieved from Vault")
	return roleID, secretID, nil
}

// writeAppRoleCredentialsToDisk writes credentials to secure files
func writeAppRoleCredentialsToDisk(rc *eos_io.RuntimeContext, roleID, secretID string) error {
	log := otelzap.Ctx(rc.Ctx)

	// Ensure secrets directory exists
	log.Info("📁 Ensuring secrets directory exists")
	if err := shared.EnsureSecretsDir(); err != nil {
		log.Error("❌ Failed to create secrets directory", zap.Error(err))
		return cerr.Wrap(err, "failed to create secrets directory")
	}

	// Write role ID
	log.Info("💾 Writing RoleID to disk", zap.String("path", shared.AppRolePaths.RoleID))
	if err := os.WriteFile(shared.AppRolePaths.RoleID, []byte(roleID), shared.OwnerReadOnly); err != nil {
		log.Error("❌ Failed to write role ID",
			zap.String("path", shared.AppRolePaths.RoleID),
			zap.Error(err))
		return cerr.Wrap(err, "failed to write role ID")
	}

	// Write secret ID
	log.Info("💾 Writing SecretID to disk", zap.String("path", shared.AppRolePaths.SecretID))
	if err := os.WriteFile(shared.AppRolePaths.SecretID, []byte(secretID), shared.OwnerReadOnly); err != nil {
		log.Error("❌ Failed to write secret ID",
			zap.String("path", shared.AppRolePaths.SecretID),
			zap.Error(err))
		return cerr.Wrap(err, "failed to write secret ID")
	}

	// Set proper ownership
	log.Info("🔒 Setting proper ownership for credential files")
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, shared.EosID)
	if err != nil {
		log.Error("❌ Failed to lookup eos user",
			zap.String("user", shared.EosID),
			zap.Error(err))
		return cerr.Wrap(err, "failed to lookup eos user")
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
	log.Info("📄 Checking agent token file", zap.String("path", tokenPath))
	if stat, err := os.Stat(tokenPath); err != nil {
		if os.IsNotExist(err) {
			log.Error("❌ Agent token file not found",
				zap.String("path", tokenPath),
				zap.Error(err))
		} else {
			log.Error("❌ Cannot stat agent token file",
				zap.String("path", tokenPath),
				zap.Error(err))
		}
		return cerr.Wrap(err, "agent token file not found")
	} else {
		log.Info("✅ Agent token file exists",
			zap.String("path", tokenPath),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()))
	}

	// Read the token
	log.Info("📖 Reading agent token")
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Error("❌ Failed to read agent token",
			zap.String("path", tokenPath),
			zap.Error(err))
		return cerr.Wrap(err, "failed to read agent token")
	}
	if len(tokenData) == 0 {
		log.Error("❌ Agent token file is empty", zap.String("path", tokenPath))
		return cerr.New("agent token file is empty")
	}
	log.Info("✅ Agent token read successfully", zap.Int("token_length", len(tokenData)))

	// Test token validity by making a simple API call
	log.Info("🔐 Creating test client with agent token")
	agentClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		log.Error("❌ Failed to create agent client", zap.Error(err))
		return cerr.Wrap(err, "failed to create agent client")
	}

	agentClient.SetToken(string(tokenData))
	agentClient.SetAddress(client.Address())

	// Simple test - lookup self
	log.Info("🧪 Validating agent token with lookup-self")
	_, err = agentClient.Auth().Token().LookupSelf()
	if err != nil {
		log.Error("❌ Agent token validation failed", zap.Error(err))
		return cerr.Wrap(err, "agent token validation failed")
	}
	log.Info("✅ Agent token is valid")

	// Check agent service status
	log.Info("🔍 Checking agent service status")
	if err := checkAgentServiceStatus(rc); err != nil {
		log.Error("❌ Agent service check failed", zap.Error(err))
		return cerr.Wrap(err, "agent service check failed")
	}

	log.Info("✅ Vault Agent functionality verified")
	return nil
}

// checkAgentServiceStatus verifies the agent service is running
func checkAgentServiceStatus(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check if service is active
	log.Info("🔍 Checking systemd service status", zap.String("service", shared.VaultAgentService))
	if err := eos_unix.CheckServiceStatus(rc.Ctx, shared.VaultAgentService); err != nil {
		log.Error("❌ Agent service not running",
			zap.String("service", shared.VaultAgentService),
			zap.Error(err))
		return cerr.Wrap(err, "agent service not running")
	}

	log.Info("✅ Vault Agent service is running", zap.String("service", shared.VaultAgentService))
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
	log.Info("📝 Writing health check script", zap.String("path", healthCheckPath))
	if err := os.WriteFile(healthCheckPath, []byte(healthCheckScript), 0755); err != nil {
		log.Error("❌ Failed to write health check script",
			zap.String("path", healthCheckPath),
			zap.Error(err))
		return cerr.Wrap(err, "failed to write health check script")
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

	log.Info("📝 Writing systemd timer", zap.String("path", timerPath))
	if err := os.WriteFile(timerPath, []byte(timerContent), 0644); err != nil {
		log.Error("❌ Failed to write health check timer",
			zap.String("path", timerPath),
			zap.Error(err))
		return cerr.Wrap(err, "failed to write health check timer")
	}

	log.Info("📝 Writing systemd service", zap.String("path", servicePath))
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		log.Error("❌ Failed to write health check service",
			zap.String("path", servicePath),
			zap.Error(err))
		return cerr.Wrap(err, "failed to write health check service")
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
