// pkg/vault/lifecycle2_enable.go
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
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
// ├── [8/12] PhasePromptAndVerRootToken(client, log)
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
	if err := PhasePromptAndVerRootToken(client, log); err != nil {
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

func EnsureAgentServiceReady(log *zap.Logger) error {
	if err := EnsureVaultAgentUnitExists(log); err != nil {
		return err
	}
	log.Info("🚀 Reloading daemon and enabling Vault Agent service")
	if err := system.ReloadDaemonAndEnable(log, shared.VaultAgentService); err != nil {
		log.Error("❌ Failed to enable/start Vault Agent service", zap.Error(err))
		return fmt.Errorf("enable/start Vault Agent service: %w", err)
	}
	return nil
}

func writeAgentPassword(password string, log *zap.Logger) error {
	log.Debug("🔏 Writing Vault Agent password to file", zap.String("path", shared.VaultAgentPassPath))

	data := []byte(password + "\n")
	if err := os.WriteFile(shared.VaultAgentPassPath, data, 0600); err != nil {
		log.Error("❌ Failed to write password file", zap.String("path", shared.VaultAgentPassPath), zap.Error(err))
		return fmt.Errorf("failed to write Vault Agent password to %s: %w", shared.VaultAgentPassPath, err)
	}

	log.Info("✅ Vault Agent password file written",
		zap.String("path", shared.VaultAgentPassPath),
		zap.Int("bytes_written", len(data)))

	return nil
}

func EnsureVaultAgentUnitExists(log *zap.Logger) error {
	if _, err := os.Stat(shared.VaultAgentServicePath); os.IsNotExist(err) {
		log.Warn("⚙️ Vault Agent systemd unit missing — creating", zap.String("path", shared.VaultAgentServicePath))
		if err := WriteAgentSystemdUnit(log); err != nil {
			log.Error("❌ Failed to write Vault Agent systemd unit", zap.Error(err))
			return fmt.Errorf("write Vault Agent unit: %w", err)
		}
		log.Info("✅ Vault Agent systemd unit ensured", zap.String("path", shared.VaultAgentServicePath))
	}
	return nil
}

func PhaseApplyCoreSecrets(client *api.Client, kvPath string, kvData map[string]string, log *zap.Logger) error {
	log.Info("[6/6] Applying core secrets to Vault", zap.String("path", kvPath))

	kv := client.KVv2("secret")

	// Sanity check: avoid nil maps
	if kvData == nil {
		log.Warn("No data provided for secret — initializing empty map")
		kvData = make(map[string]string)
	}

	// Marshal as {"json": "..."}
	data, err := json.Marshal(kvData)
	if err != nil {
		return fmt.Errorf("failed to marshal KV data: %w", err)
	}
	payload := map[string]interface{}{"json": string(data)}

	// Write to Vault
	if _, err := kv.Put(context.Background(), kvPath, payload); err != nil {
		return fmt.Errorf("failed to write secret at %s: %w", kvPath, err)
	}

	log.Info("✅ Secret written to Vault", zap.String("path", kvPath), zap.Int("keys", len(kvData)))
	return nil
}
