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
		return fmt.Errorf("vault health check failed: %w", err)
	}
	if !healthy {
		return fmt.Errorf("vault is unhealthy after check")
	}

	log.Info("[8/12] Validating root token")
	if err := PhasePromptAndValidateRootToken(client, log); err != nil {
		return err
	}

	log.Info("[9/12] Enabling auth methods and applying policies")
	if err := PhaseEnableAuthMethodsAndPolicies(client, log); err != nil {
		return err
	}

	log.Info("[10/12] Creating AppRole for EOS")
	if err := PhaseCreateAppRole(client, log); err != nil {
		return err
	}

	log.Info("[11/12] Rendering Vault Agent config")
	if err := PhaseRenderVaultAgentConfig(client, log); err != nil {
		return err
	}

	log.Info("[12/12] Starting Vault Agent and validating token")
	if err := PhaseStartVaultAgentAndValidate(client, log); err != nil {
		return err
	}

	log.Info("✅ Vault enable sequence complete 🎉")
	return nil
}
func ApplyCoreSecretsAndHealthCheck(client *api.Client, log *zap.Logger) error {
	if err := PhaseApplyCoreSecrets(client, shared.VaultTestPath, map[string]string{"example_key": "example_value"}, log); err != nil {
		return err
	}

	healthy, err := CheckVaultHealth(log)
	if err != nil || !healthy {
		return fmt.Errorf("vault unhealthy after setup: %w", err)
	}
	return nil
}
