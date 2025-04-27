// pkg/vault/lifecycle2_enable.go
package vault

import (
	"fmt"

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

// EnableVault orchestrates enabling an initialized Vault instance.
func EnableVault(client *api.Client, log *zap.Logger) error {
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
	if err := PhaseCreateAppRole(client, log); err != nil {
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
