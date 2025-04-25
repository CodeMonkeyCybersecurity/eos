// pkg/vault/lifecycle_policy.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

/**/
// ## 9. Upload EOS Vault Policy
// EnsurePolicy writes the eos-policy defined in pkg/vault/types.go
// - `EnsureEosPolicy(client *api.Client, log *zap.Logger) error`

// EnsurePolicy writes the eos-policy defined in pkg/vault/types.go
func EnsurePolicy(client *api.Client, log *zap.Logger) error {
	log.Info("📝 Preparing to write Vault policy", zap.String("policy", shared.EosVaultPolicy))

	// 1️⃣ Retrieve the policy from internal map
	pol, ok := shared.Policies[shared.EosVaultPolicy]
	if !ok {
		log.Error("❌ Policy not found in internal map", zap.String("policy", shared.EosVaultPolicy))
		return fmt.Errorf("internal error: policy %q not found in shared.Policies map", shared.EosVaultPolicy)
	}

	// 2️⃣ Log metadata about the policy string
	log.Debug("📄 Policy loaded", zap.String("preview", truncatePolicy(pol)), zap.Int("length", len(pol)))

	// 3️⃣ Write policy to Vault
	log.Info("📡 Writing policy to Vault")
	if err := client.Sys().PutPolicy(shared.EosVaultPolicy, pol); err != nil {
		log.Error("❌ Failed to write policy", zap.String("policy", shared.EosVaultPolicy), zap.Error(err))
		return fmt.Errorf("failed to write policy %s: %w", shared.EosVaultPolicy, err)
	}

	// 4️⃣ Validate policy by re-fetching it from Vault
	log.Info("🔍 Verifying policy write")
	storedPol, err := client.Sys().GetPolicy(shared.EosVaultPolicy)
	if err != nil {
		log.Error("❌ Failed to retrieve policy for verification", zap.Error(err))
		return fmt.Errorf("failed to verify written policy: %w", err)
	}

	if strings.TrimSpace(storedPol) != strings.TrimSpace(pol) {
		log.Warn("⚠️ Policy mismatch detected after write",
			zap.String("expected_preview", truncatePolicy(pol)),
			zap.String("stored_preview", truncatePolicy(storedPol)))
		return fmt.Errorf("written policy does not match expected content")
	}

	log.Info("✅ Policy successfully written and verified", zap.String("policy", shared.EosVaultPolicy))
	return nil
}

// truncatePolicy returns a trimmed preview for debug logging
func truncatePolicy(policy string) string {
	policy = strings.TrimSpace(policy)
	if len(policy) > 100 {
		return policy[:100] + "..."
	}
	return policy
}

// ApplyAdminPolicy applies a full-access policy from the Policies map to the eos user.
func ApplyAdminPolicy(creds UserpassCreds, client *api.Client, log *zap.Logger) error {
	fmt.Println("Creating full-access policy for eos.")

	policyName := shared.EosVaultPolicy
	policy, ok := shared.Policies[policyName]
	if !ok {
		return fmt.Errorf("policy %q not found in Policies map", policyName)
	}

	// Apply policy using the Vault API.
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		log.Error("Failed to apply policy via API", zap.Error(err))
		return err
	}
	log.Info("✅ Custom policy applied via API", zap.String("policy", policyName))

	// Update the eos user with the policy.
	_, err := client.Logical().Write(shared.EosVaultUserPath, map[string]interface{}{
		"password": creds.Password,
		"policies": policyName,
	})
	if err != nil {
		log.Error("Failed to update eos user with policy", zap.Error(err))
		return err
	}
	log.Info("✅ eos user updated with full privileges", zap.String("policy", policyName))
	return nil
}

