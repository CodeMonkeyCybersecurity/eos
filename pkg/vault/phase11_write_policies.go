// pkg/vault/phase11_write_policies.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

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
		return fmt.Errorf("failed to write eos-policy to Vault during Phase 9: %w", err)
	}

	// 4️⃣ Validate policy by re-fetching it from Vault
	log.Info("🔍 Verifying policy write")
	storedPol, err := client.Sys().GetPolicy(shared.EosVaultPolicy)
	if err != nil {
		log.Error("❌ Failed to retrieve policy for verification", zap.Error(err))
		return fmt.Errorf("failed to verify written policy: %w", err)
	}
	if strings.TrimSpace(storedPol) != strings.TrimSpace(pol) {
		log.Error("🚨 Policy mismatch after write",
			zap.String("expected_preview", truncatePolicy(pol)),
			zap.String("stored_preview", truncatePolicy(storedPol)))
		return fmt.Errorf("policy mismatch after write — vault contents are inconsistent")
	}

	log.Info("✅ Policy successfully written and verified", zap.String("policy", shared.EosVaultPolicy))
	return nil
}

// ApplyAdminPolicy applies a full-access policy from the Policies map to the eos user.
func ApplyAdminPolicy(creds shared.UserpassCreds, client *api.Client, log *zap.Logger) error {
	log.Info("🔐 Creating full-access policy for eos user")
	log.Debug("Applying admin policy to eos user", zap.Int("password_len", len(creds.Password)))

	policyName := shared.EosVaultPolicy
	policy, ok := shared.Policies[policyName]
	if !ok {
		return fmt.Errorf("policy %q not found in Policies map", policyName)
	}

	// Step 1: Apply eos-policy itself
	log.Info("📜 Uploading custom policy to Vault", zap.String("policy", policyName))
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		log.Error("❌ Failed to apply policy via API", zap.Error(err))
		return fmt.Errorf("failed to upload policy %q: %w", policyName, err)
	}
	log.Info("✅ Policy applied to Vault", zap.String("policy", policyName))

	// Step 2: Create eos user with userpass auth, targeting KVv2
	log.Info("🔑 Creating eos user in KVv2")
	data := map[string]interface{}{
		"password": creds.Password,
		"policies": policyName,
	}
	if err := WriteKVv2(client, "secret", "users/eos", data, log); err != nil {
		log.Error("❌ Failed to create eos user in Vault", zap.Error(err))
		return fmt.Errorf("failed to write eos user credentials: %w", err)
	}

	log.Info("✅ eos user created with full privileges", zap.String("user", "eos"), zap.String("policy", policyName))
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
