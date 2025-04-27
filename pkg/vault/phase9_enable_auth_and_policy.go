// pkg/vault/phase9_enable_auth_and_policy.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 9. Enable Auth Methods and Apply Policies
//--------------------------------------------------------------------

// PHASE 9 — PhaseEnableAuthMethodsAndPolicies()
//           └── EnableUserPass()
//           └── EnsureVaultAuthEnabled()
//           └── EnsurePolicy()
//           └── ApplyAdminPolicy()

// PhaseEnableAuthMethodsAndPolicies enables Vault auth methods and applies the EOS policy.
func PhaseEnableAuthMethodsAndPolicies(client *api.Client, log *zap.Logger) error {
	log.Info("🛡️ [Phase 9] Enabling auth methods and policies")

	// PRECHECK for KV
	exists, err := IsMountEnabled(client, shared.VaultMountKV)
	if err != nil {
		return fmt.Errorf("precheck mount failed: %w", err)
	}
	if !exists {
		log.Warn("⚠️ KV engine missing — attempting to enable KVv2 at mount=secret/")
		if err := enableMount(client, shared.VaultMountKV, "kv", map[string]string{"version": "2"}, "✅ KVv2 enabled at secret/"); err != nil {
			return fmt.Errorf("failed to enable KVv2 at secret/: %w", err)
		}
	}
	log.Info("✅ KVv2 mount successfully enabled", zap.String("mount", shared.VaultMountKV))

	// Proceed with auth enablement and policies
	if err := EnableUserPass(client); err != nil {
		return fmt.Errorf("enable userpass auth method: %w", err)
	}

	if err := EnsureVaultAuthEnabled(client, "userpass", "auth/userpass", log); err != nil {
		return fmt.Errorf("ensure userpass auth enabled: %w", err)
	}

	if err := EnsureVaultAuthEnabled(client, "approle", "auth/approle", log); err != nil {
		return fmt.Errorf("ensure approle auth enabled: %w", err)
	}

	if err := EnsurePolicy(client, log); err != nil {
		return fmt.Errorf("apply EOS policy: %w", err)
	}

	eosCreds, err := PromptForEosPassword(log)
	if err != nil {
		return fmt.Errorf("prompt eos password: %w", err)
	}

	if len(eosCreds.Password) < 8 {
		log.Error("eos user password too short", zap.Int("length", len(eosCreds.Password)))
		return fmt.Errorf("eos password must be at least 8 characters")
	}

	// This is safe because the mount exists
	if err := ApplyAdminPolicy(*eosCreds, client, log); err != nil {
		return fmt.Errorf("apply admin policy: %w", err)
	}

	log.Info("✅ Auth methods and policies enabled successfully")
	return nil
}

// Enable UserPass
func EnableUserPass(client *api.Client) error {
	return enableAuth(client, "userpass")
}

func EnsureVaultAuthEnabled(client *api.Client, method, path string, log *zap.Logger) error {
	existing, err := client.Sys().ListAuth()
	if err != nil {
		return err
	}
	if _, ok := existing[path]; ok {
		return nil
	}
	return client.Sys().EnableAuthWithOptions(strings.TrimSuffix(path, "/"), &api.EnableAuthOptions{Type: method})
}

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
	log.Debug("Applying admin policy to eos user (password length verified)", zap.Int("password_len", len(creds.Password)))

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

// truncatePolicy returns a trimmed preview for debug logging
func truncatePolicy(policy string) string {
	policy = strings.TrimSpace(policy)
	if len(policy) > 100 {
		return policy[:100] + "..."
	}
	return policy
}

// IsMountEnabled checks whether a Vault mount exists at the given path.
func IsMountEnabled(client *api.Client, mount string) (bool, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false, err
	}
	_, exists := mounts[mount]
	return exists, nil
}

// Enable KV v2
func EnableKV2(client *api.Client, log *zap.Logger) error {
	log.Info("⚙️ Enabling KVv2 engine at mount=secret/")
	return enableMount(client, shared.VaultMountKV, "kv", map[string]string{"version": "2"}, "✅ KVv2 enabled at path=secret/")
}
