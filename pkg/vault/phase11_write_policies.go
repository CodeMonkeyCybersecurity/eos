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
func EnsurePolicy(client *api.Client) error {
	zap.L().Info("📝 Preparing to write Vault policy", zap.String("policy", shared.EosVaultPolicy))

	// 1️⃣ Retrieve the policy from internal map
	pol, ok := shared.Policies[shared.EosVaultPolicy]
	if !ok {
		zap.L().Error("❌ Policy not found in internal map", zap.String("policy", shared.EosVaultPolicy))
		return fmt.Errorf("internal error: policy %q not found in shared.Policies map", shared.EosVaultPolicy)
	}

	// 2️⃣ Log metadata about the policy string
	zap.L().Debug("📄 Policy loaded", zap.String("preview", truncatePolicy(pol)), zap.Int("length", len(pol)))

	// 3️⃣ Write policy to Vault
	zap.L().Info("📡 Writing policy to Vault")
	if err := client.Sys().PutPolicy(shared.EosVaultPolicy, pol); err != nil {
		zap.L().Error("❌ Failed to write policy", zap.String("policy", shared.EosVaultPolicy), zap.Error(err))
		return fmt.Errorf("failed to write eos-policy to Vault during Phase 9: %w", err)
	}

	// 4️⃣ Validate policy by re-fetching it from Vault
	zap.L().Info("🔍 Verifying policy write")
	storedPol, err := client.Sys().GetPolicy(shared.EosVaultPolicy)
	if err != nil {
		zap.L().Error("❌ Failed to retrieve policy for verification", zap.Error(err))
		return fmt.Errorf("failed to verify written policy: %w", err)
	}
	if strings.TrimSpace(storedPol) != strings.TrimSpace(pol) {
		zap.L().Error("🚨 Policy mismatch after write",
			zap.String("expected_preview", truncatePolicy(pol)),
			zap.String("stored_preview", truncatePolicy(storedPol)))
		return fmt.Errorf("policy mismatch after write — vault contents are inconsistent")
	}

	zap.L().Info("✅ Policy successfully written and verified", zap.String("policy", shared.EosVaultPolicy))

	// Attach policy to AppRole
	if err := AttachPolicyToAppRole(client, zap.L()); err != nil {
		return fmt.Errorf("failed to attach eos-policy to AppRole: %w", err)
	}

	return nil
}

// ApplyAdminPolicy applies a full-access policy from the Policies map to the eos user.
func ApplyAdminPolicy(creds shared.UserpassCreds, client *api.Client) error {
	zap.L().Info("🔐 Creating full-access policy for eos user")
	zap.L().Debug("Applying admin policy to eos user", zap.Int("password_len", len(creds.Password)))

	policyName := shared.EosVaultPolicy
	policy, ok := shared.Policies[policyName]
	if !ok {
		return fmt.Errorf("policy %q not found in Policies map", policyName)
	}

	// Step 1: Apply eos-policy itself
	zap.L().Info("📜 Uploading custom policy to Vault", zap.String("policy", policyName))
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		zap.L().Error("❌ Failed to apply policy via API", zap.Error(err))
		return fmt.Errorf("failed to upload policy %q: %w", policyName, err)
	}
	zap.L().Info("✅ Policy applied to Vault", zap.String("policy", policyName))

	// Step 2: Create eos user with userpass auth, targeting KVv2
	zap.L().Info("🔑 Creating eos user in KVv2")
	data := map[string]interface{}{
		"password": creds.Password,
		"policies": policyName,
	}
	if err := WriteKVv2(client, "secret", "users/eos", data); err != nil {
		zap.L().Error("❌ Failed to create eos user in Vault", zap.Error(err))
		return fmt.Errorf("failed to write eos user credentials: %w", err)
	}

	zap.L().Info("✅ eos user created with full privileges", zap.String("user", "eos"), zap.String("policy", policyName))
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

// AttachPolicyToAppRole ensures eos-policy is attached to eos-approle
func AttachPolicyToAppRole(client *api.Client, log *zap.Logger) error {
	rolePath := "auth/approle/role/eos-approle"

	log.Info("🔑 Attaching eos-policy to eos-approle", zap.String("role_path", rolePath))

	// Prepare role update payload
	data := map[string]interface{}{
		"policies": shared.EosVaultPolicy,
	}

	// Write to the AppRole configuration
	_, err := client.Logical().Write(rolePath, data)
	if err != nil {
		log.Error("❌ Failed to attach policy to AppRole", zap.Error(err))
		return fmt.Errorf("failed to attach eos-policy to eos-approle: %w", err)
	}

	log.Info("✅ eos-policy successfully attached to eos-approle", zap.String("policy", shared.EosVaultPolicy))
	return nil
}
