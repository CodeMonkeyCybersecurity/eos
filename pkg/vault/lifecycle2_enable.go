// pkg/vault/lifecycle2_enable.go
package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 7.  Check Vault Health
// 8.  Validate Root Token
// 9.  Enable Auth Methods and Apply Policies
// 10. Create AppRole for EOS
// 11. Render Vault Agent Config
// 12. Start Vault Agent and Validate
//--------------------------------------------------------------------

// EnableVault
// ├── [7/12] CheckVaultHealth()
// │   └── (checks Vault server health)
// ├── [8/12] PhasePromptAndValidateRootToken(client, log)
// │   └── (prompts or loads root token, validates it)
// ├── [9/12] PhaseEnableAuthMethodsAndPolicies(client, log)
// │   └── (enables auth backends, policies, admin user, audit logs)
// ├── [10/12] PhaseCreateAppRole(client, log, password)
// │   ├── DefaultAppRoleOptions()
// │   ├── EnsureAppRole(client, log, opts)
// │   │   ├── os.Stat(role_id path) (check if AppRole files exist)
// │   │   ├── refreshAppRoleCreds(client, log) (if RefreshCreds true)
// │   │   ├── EnableAppRoleAuth(client, log) (if approle auth not mounted)
// │   │   ├── client.Logical().Write(role definition)
// │   │   ├── refreshAppRoleCreds(client, log) (fetch role_id/secret_id)
// │   │   └── WriteAppRoleFiles(roleID, secretID, log)
// │   │       ├── system.EnsureOwnedDir()
// │   │       └── system.WriteOwnedFile()
// │   ├── writeAgentPassword(password, log) (only if password != "")
// │   ├── WriteAgentSystemdUnit(log)
// │   └── EnsureAgentServiceReady(log)
// │       ├── EnsureVaultAgentUnitExists(log)
// │       └── system.ReloadDaemonAndEnable()
// ├── [11/12] PhaseRenderVaultAgentConfig(client, log)
// │   └── (renders /etc/vault-agent-eos.hcl from template)
// ├── [12/12] PhaseStartVaultAgentAndValidate(client, log)
// │   ├── StartVaultAgentService(log)
// │   ├── WaitForAgentToken(path, log)
// │   ├── readTokenFromSink(path)
// │   └── SetVaultToken(client, token)
// ├── Final Validation: ApplyCoreSecretsAndHealthCheck(client, log)
// │   ├── PhaseApplyCoreSecrets(client, mountPath, dataMap, log)
// │   │   └── (writes example_key=example_value to Vault KVv2)
// │   └── CheckVaultHealth()
// │       └── (confirms Vault is still healthy)
// └── Final: "Vault passed final readiness check — installation complete 🎉"

// EnableVault orchestrates enabling an initialized Vault instance.
func EnableVault(client *api.Client, log *zap.Logger, password string) error {
	log.Info("[7/12] Checking Vault health status")
	healthy, err := CheckVaultHealth(log)
	if err != nil {
		return fmt.Errorf("phase 7 (check health): %w", err)
	}
	if !healthy {
		return fmt.Errorf("vault is unhealthy after phase 7 health check")
	}

	log.Info("[8/12] Validating root token")
	if err := PhasePromptAndValidateRootToken(client, log); err != nil {
		return fmt.Errorf("phase 8 (validate root token): %w", err)
	}

	log.Info("[9/12] Enabling auth methods and applying policies")
	if err := PhaseEnableAuthMethodsAndPolicies(client, log); err != nil {
		return fmt.Errorf("phase 9 (enable auth methods and policies): %w", err)
	}

	log.Info("[10/12] Creating AppRole for EOS")
	if _, _, err := PhaseCreateAppRole(client, log, password); err != nil {
		return fmt.Errorf("phase 10 (create AppRole): %w", err)
	}

	log.Info("[11/12] Rendering Vault Agent config")
	if err := PhaseRenderVaultAgentConfig(client, log); err != nil {
		return fmt.Errorf("phase 11 (render agent config): %w", err)
	}

	log.Info("[12/12] Starting Vault Agent and validating token")
	if err := PhaseStartVaultAgentAndValidate(client, log); err != nil {
		return fmt.Errorf("phase 12 (start agent and validate): %w", err)
	}

	log.Info("🔎 Verifying Vault readiness with test secret")
	if err := ApplyCoreSecretsAndHealthCheck(client, log); err != nil {
		log.Warn("⚠️ Vault health recheck failed after enable", zap.Error(err))
		return logger.LogErrAndWrap(log, "post-enable vault healthcheck", err)
	}
	log.Info("✅ Vault passed final readiness check — installation complete 🎉")
	log.Info("✅ Vault enable sequence complete 🎉 — Vault is operational")
	return nil
}

// ApplyCoreSecretsAndHealthCheck uploads example secrets and checks Vault health again.
func ApplyCoreSecretsAndHealthCheck(client *api.Client, log *zap.Logger) error {
	log.Info("🔐 Applying core secrets and rechecking Vault health")

	if err := PhaseApplyCoreSecrets(client, shared.VaultTestPath, map[string]string{"example_key": "example_value"}, log); err != nil {
		return fmt.Errorf("apply core secrets: %w", err)
	}

	healthy, err := CheckVaultHealth(log)
	if err != nil {
		return fmt.Errorf("vault health recheck failed: %w", err)
	}
	if !healthy {
		return fmt.Errorf("vault unhealthy after core secrets phase")
	}

	log.Info("✅ Core secrets applied and Vault healthy")
	return nil
}
