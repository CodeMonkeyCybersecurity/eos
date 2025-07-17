package vault_salt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// Enable enables Vault features using SaltStack
func Enable(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault feature enablement via Salt")
	
	// ASSESS - Check prerequisites
	logger.Info("Assessing prerequisites for Vault enablement")
	if err := checkEnablePrerequisites(rc, config); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}
	
	// Get root token for configuration
	rootToken, err := getRootToken(rc)
	if err != nil {
		return fmt.Errorf("failed to get root token: %w", err)
	}
	
	// INTERVENE - Execute Salt state
	logger.Info("Executing Salt state for Vault enablement")
	if err := executeSaltEnable(rc, config, rootToken); err != nil {
		return fmt.Errorf("salt enablement failed: %w", err)
	}
	
	// EVALUATE - Verify enablement
	logger.Info("Verifying Vault feature enablement")
	if err := verifyEnablement(rc, config); err != nil {
		return fmt.Errorf("enablement verification failed: %w", err)
	}
	
	logger.Info("Vault feature enablement completed successfully")
	return nil
}

func checkEnablePrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Salt is available
	cli := eos_cli.New(rc)
	if _, err := cli.ExecString("salt-call", "--version"); err != nil {
		logger.Error("Salt is not available", zap.Error(err))
		return eos_err.NewUserError("salt is not available")
	}
	
	// Check if Vault is installed
	if _, err := cli.ExecString("vault", "version"); err != nil {
		logger.Error("Vault is not installed", zap.Error(err))
		return eos_err.NewUserError("vault is not installed")
	}
	
	// Check if Vault service is running
	output, err := cli.ExecString("systemctl", "is-active", VaultServiceName)
	if err != nil || strings.TrimSpace(output) != "active" {
		return eos_err.NewUserError("vault service is not running")
	}
	
	// Check Vault status
	statusOutput, err := cli.ExecString("vault", "status", "-format=json")
	if err != nil && !strings.Contains(err.Error(), "exit status 2") {
		return fmt.Errorf("failed to check vault status: %w", err)
	}
	
	var status VaultStatus
	if err := json.Unmarshal([]byte(statusOutput), &status); err == nil {
		if !status.Initialized {
			return eos_err.NewUserError("vault is not initialized")
		}
		if status.Sealed {
			return eos_err.NewUserError("vault is sealed")
		}
	}
	
	logger.Info("Enable prerequisites check passed")
	return nil
}

func getRootToken(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Try to read from init file
	initData, err := os.ReadFile(VaultInitDataFile)
	if err != nil {
		logger.Warn("Failed to read init data file",
			zap.String("file", VaultInitDataFile),
			zap.Error(err))
		
		// Prompt for root token
		logger.Info("terminal prompt: Please enter Vault root token")
		token, err := eos_io.PromptInput(rc, "Vault root token: ", "")
		if err != nil {
			return "", fmt.Errorf("failed to read root token: %w", err)
		}
		return strings.TrimSpace(token), nil
	}
	
	var vaultInit VaultInitResponse
	if err := json.Unmarshal(initData, &vaultInit); err != nil {
		return "", fmt.Errorf("failed to parse init data: %w", err)
	}
	
	if vaultInit.RootToken == "" {
		return "", fmt.Errorf("root token not found in init data")
	}
	
	logger.Info("Retrieved root token from init data")
	return vaultInit.RootToken, nil
}

func executeSaltEnable(rc *eos_io.RuntimeContext, config *Config, rootToken string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Set Vault environment variables
	vaultAddr := fmt.Sprintf("https://127.0.0.1:%d", config.Port)
	if config.TLSDisable {
		vaultAddr = fmt.Sprintf("http://127.0.0.1:%d", config.Port)
	}
	
	// Prepare Salt pillar data
	pillarData := map[string]interface{}{
		"vault": map[string]interface{}{
			"addr":               vaultAddr,
			"token":              rootToken,
			"skip_verify":        true,
			"enable_userpass":    config.EnableUserpass,
			"enable_approle":     config.EnableAppRole,
			"enable_mfa":         config.EnableMFA,
			"enable_audit":       config.EnableAudit,
			"enable_policies":    config.EnablePolicies,
			"audit_log_path":     AuditLogFilePath,
			"hecate_integration": config.HecateIntegration,
			"delphi_integration": config.DelphiIntegration,
		},
	}
	
	// Add policy configurations
	if config.EnablePolicies {
		pillarData["vault"].(map[string]interface{})["policies"] = map[string]interface{}{
			"admin": map[string]interface{}{
				"name": AdminPolicyName,
				"rules": `
# Admin policy - full access
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}`,
			},
			"readonly": map[string]interface{}{
				"name": ReadOnlyPolicyName,
				"rules": `
# Read-only policy
path "*" {
  capabilities = ["read", "list"]
}`,
			},
			"eos-app": map[string]interface{}{
				"name": "eos-app",
				"rules": `
# Eos application policy
path "secret/data/eos/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/eos/*" {
  capabilities = ["list", "read"]
}`,
			},
		}
	}
	
	// Add auth method configurations
	if config.EnableUserpass {
		pillarData["vault"].(map[string]interface{})["userpass"] = map[string]interface{}{
			"users": []map[string]interface{}{
				{
					"username": "eos-admin",
					"policies": []string{AdminPolicyName},
				},
				{
					"username": "eos-readonly",
					"policies": []string{ReadOnlyPolicyName},
				},
			},
		}
	}
	
	if config.EnableAppRole {
		pillarData["vault"].(map[string]interface{})["approle"] = map[string]interface{}{
			"roles": []map[string]interface{}{
				{
					"role_name":   "eos-app",
					"policies":    []string{"eos-app"},
					"token_ttl":   "1h",
					"token_max_ttl": "24h",
				},
			},
		}
	}
	
	pillarJSON, err := json.Marshal(pillarData)
	if err != nil {
		return fmt.Errorf("failed to marshal pillar data: %w", err)
	}
	
	// Execute Salt state
	args := []string{
		"--local",
		"--file-root=" + config.SaltFileRoot,
		"--pillar-root=" + config.SaltPillarRoot,
		"state.apply",
		SaltStateVaultEnable,
		"--output=json",
		"--output-indent=2",
		fmt.Sprintf("pillar='%s'", string(pillarJSON)),
	}
	
	// Set environment variables for Salt execution
	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=%s", VaultAddrEnvVar, vaultAddr))
	env = append(env, fmt.Sprintf("%s=%s", VaultTokenEnvVar, rootToken))
	env = append(env, fmt.Sprintf("%s=true", VaultSkipVerifyEnvVar))
	
	logger.Info("Executing Salt state",
		zap.String("state", SaltStateVaultEnable),
		zap.Bool("userpass", config.EnableUserpass),
		zap.Bool("approle", config.EnableAppRole),
		zap.Bool("mfa", config.EnableMFA),
		zap.Bool("audit", config.EnableAudit),
		zap.Bool("policies", config.EnablePolicies))
	
	// Execute with environment variables
	os.Setenv(VaultAddrEnvVar, vaultAddr)
	os.Setenv(VaultTokenEnvVar, rootToken)
	os.Setenv(VaultSkipVerifyEnvVar, "true")
	defer func() {
		os.Unsetenv(VaultAddrEnvVar)
		os.Unsetenv(VaultTokenEnvVar)
		os.Unsetenv(VaultSkipVerifyEnvVar)
	}()
	
	cli := eos_cli.WithTimeout(rc, config.SaltTimeout)
	output, err := cli.ExecString("salt-call", args...)
	if err != nil {
		logger.Error("Salt state execution failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("salt state execution failed: %w", err)
	}
	
	// Parse Salt output
	if err := parseSaltOutput(output); err != nil {
		return fmt.Errorf("salt state failed: %w", err)
	}
	
	// Configure Vault agent if needed
	if config.EnableAppRole {
		logger.Info("Configuring Vault agent service")
		if err := configureVaultAgent(rc, config, vaultAddr); err != nil {
			logger.Warn("Failed to configure Vault agent",
				zap.Error(err))
			// Not a fatal error
		}
	}
	
	logger.Info("Salt enable state executed successfully")
	return nil
}

func configureVaultAgent(rc *eos_io.RuntimeContext, config *Config, vaultAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Vault agent configuration
	agentConfig := map[string]interface{}{
		"vault": map[string]interface{}{
			"address": vaultAddr,
			"tls_skip_verify": true,
		},
		"auto_auth": map[string]interface{}{
			"method": map[string]interface{}{
				"type": "approle",
				"config": map[string]interface{}{
					"role_id_file_path":   "/etc/vault.d/role-id",
					"secret_id_file_path": "/etc/vault.d/secret-id",
				},
			},
			"sink": []map[string]interface{}{
				{
					"type": "file",
					"config": map[string]interface{}{
						"path": "/etc/vault.d/vault-token",
					},
				},
			},
		},
		"cache": map[string]interface{}{
			"use_auto_auth_token": true,
		},
		"listener": map[string]interface{}{
			"tcp": map[string]interface{}{
				"address":     "127.0.0.1:8100",
				"tls_disable": true,
			},
		},
	}
	
	// Write agent configuration
	agentConfigPath := filepath.Join(config.ConfigPath, VaultAgentConfigFile)
	agentConfigJSON, err := json.MarshalIndent(agentConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal agent config: %w", err)
	}
	
	if err := os.WriteFile(agentConfigPath, agentConfigJSON, 0644); err != nil {
		return fmt.Errorf("failed to write agent config: %w", err)
	}
	
	logger.Info("Vault agent configuration created",
		zap.String("path", agentConfigPath))
	
	return nil
}

func verifyEnablement(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Vault client
	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		return fmt.Errorf("failed to read vault environment: %w", err)
	}
	
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}
	
	// Get root token for verification
	rootToken, err := getRootToken(rc)
	if err != nil {
		return fmt.Errorf("failed to get root token: %w", err)
	}
	
	client.SetToken(rootToken)
	
	// Verify auth methods
	if config.EnableUserpass {
		auths, err := client.Sys().ListAuth()
		if err != nil {
			return fmt.Errorf("failed to list auth methods: %w", err)
		}
		
		if _, ok := auths["userpass/"]; !ok {
			return fmt.Errorf("userpass auth method not enabled")
		}
		logger.Info("Userpass auth method verified")
	}
	
	if config.EnableAppRole {
		auths, err := client.Sys().ListAuth()
		if err != nil {
			return fmt.Errorf("failed to list auth methods: %w", err)
		}
		
		if _, ok := auths["approle/"]; !ok {
			return fmt.Errorf("approle auth method not enabled")
		}
		logger.Info("AppRole auth method verified")
	}
	
	// Verify audit devices
	if config.EnableAudit {
		audits, err := client.Sys().ListAudit()
		if err != nil {
			return fmt.Errorf("failed to list audit devices: %w", err)
		}
		
		if len(audits) == 0 {
			return fmt.Errorf("no audit devices enabled")
		}
		
		for name, audit := range audits {
			logger.Info("Audit device verified",
				zap.String("name", name),
				zap.String("type", audit.Type))
		}
	}
	
	// Verify policies
	if config.EnablePolicies {
		policies, err := client.Sys().ListPolicies()
		if err != nil {
			return fmt.Errorf("failed to list policies: %w", err)
		}
		
		expectedPolicies := []string{AdminPolicyName, ReadOnlyPolicyName, "eos-app"}
		for _, expected := range expectedPolicies {
			found := false
			for _, policy := range policies {
				if policy == expected {
					found = true
					break
				}
			}
			if !found {
				logger.Warn("Expected policy not found",
					zap.String("policy", expected))
			} else {
				logger.Debug("Policy verified",
					zap.String("policy", expected))
			}
		}
	}
	
	logger.Info("Vault feature enablement verified successfully")
	return nil
}