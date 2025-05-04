package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func EnsurePolicy() error {
	zap.L().Info("📝 Preparing to write Vault policy", zap.String("policy", shared.EosVaultPolicy))

	client, err := GetPrivilegedVaultClient()
	if err != nil {
		zap.L().Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	pol, ok := shared.Policies[shared.EosVaultPolicy]
	if !ok {
		zap.L().Error("❌ Policy not found in internal map", zap.String("policy", shared.EosVaultPolicy))
		return fmt.Errorf("internal error: policy %q not found in shared.Policies map", shared.EosVaultPolicy)
	}

	zap.L().Debug("📄 Policy loaded", zap.String("preview", truncatePolicy(pol)), zap.Int("length", len(pol)))

	zap.L().Info("📡 Writing policy to Vault")
	if err := client.Sys().PutPolicy(shared.EosVaultPolicy, pol); err != nil {
		zap.L().Error("❌ Failed to write policy", zap.String("policy", shared.EosVaultPolicy), zap.Error(err))
		return fmt.Errorf("failed to write eos-policy to Vault during Phase 9: %w", err)
	}

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

	if err := AttachPolicyToAppRole(client, zap.L()); err != nil {
		return fmt.Errorf("failed to attach eos-policy to AppRole: %w", err)
	}

	return nil
}

func ApplyAdminPolicy(creds shared.UserpassCreds, client *api.Client) error {
	zap.L().Info("🔐 Creating full-access policy for eos user")
	zap.L().Debug("Applying admin policy to eos user", zap.Int("password_len", len(creds.Password)))

	policyName := shared.EosVaultPolicy
	policy, ok := shared.Policies[policyName]
	if !ok {
		return fmt.Errorf("policy %q not found in Policies map", policyName)
	}

	zap.L().Info("📜 Uploading custom policy to Vault", zap.String("policy", policyName))
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		zap.L().Error("❌ Failed to apply policy via API", zap.Error(err))
		return fmt.Errorf("failed to upload policy %q: %w", policyName, err)
	}
	zap.L().Info("✅ Policy applied to Vault", zap.String("policy", policyName))

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

func truncatePolicy(policy string) string {
	policy = strings.TrimSpace(policy)
	if len(policy) > 100 {
		return policy[:100] + "..."
	}
	return policy
}

func AttachPolicyToAppRole(existingClient *api.Client, log *zap.Logger) error {
	rolePath := "auth/approle/role/eos-approle"

	client, err := GetPrivilegedVaultClient()
	if err != nil {
		log.Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	log.Info("🔑 Attaching eos-policy to eos-approle", zap.String("role_path", rolePath))

	data := map[string]interface{}{
		"policies": shared.EosVaultPolicy,
	}

	_, err = client.Logical().Write(rolePath, data)
	if err != nil {
		log.Error("❌ Failed to attach policy to AppRole", zap.Error(err))
		return fmt.Errorf("failed to attach eos-policy to eos-approle: %w", err)
	}

	log.Info("✅ eos-policy successfully attached to eos-approle", zap.String("policy", shared.EosVaultPolicy))
	return nil
}
