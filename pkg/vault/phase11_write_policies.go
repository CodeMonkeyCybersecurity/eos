package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func EnsurePolicy() error {
	policyName := shared.EosDefaultPolicyName
	zap.L().Info("📝 Preparing to write Vault policy", zap.String("policy", policyName))

	client, err := GetRootClient()
	if err != nil {
		zap.L().Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	pol, err := shared.RenderEosPolicy("users")
	if err != nil {
		zap.L().Error("❌ Failed to render policy template", zap.Error(err))
		return fmt.Errorf("render policy template: %w", err)
	}

	zap.L().Debug("📄 Policy loaded", zap.String("preview", truncatePolicy(pol)), zap.Int("length", len(pol)))

	zap.L().Info("📡 Writing policy to Vault")
	if err := client.Sys().PutPolicy(policyName, pol); err != nil {
		zap.L().Error("❌ Failed to write policy", zap.String("policy", policyName), zap.Error(err))
		return fmt.Errorf("failed to write eos-policy to Vault: %w", err)
	}

	zap.L().Info("🔍 Verifying policy write")
	storedPol, err := client.Sys().GetPolicy(policyName)
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

	zap.L().Info("✅ Policy successfully written and verified", zap.String("policy", policyName))

	if err := AttachPolicyToAppRole(client, zap.L()); err != nil {
		return fmt.Errorf("failed to attach eos-policy to AppRole: %w", err)
	}

	if err := AttachPolicyToEosEntity(client, zap.L()); err != nil {
		return fmt.Errorf("failed to attach eos-policy to eos entity: %w", err)
	}

	return nil
}

func AttachPolicyToEosEntity(client *api.Client, log *zap.Logger) error {
	entityName := shared.EosID
	entityLookupPath := fmt.Sprintf(shared.EosEntityLookupPath, entityName)

	// Check if entity exists
	entityResp, err := client.Logical().Read(entityLookupPath)
	var entityID string
	if err != nil {
		return fmt.Errorf("failed to look up entity: %w", err)
	}
	if entityResp != nil && entityResp.Data != nil {
		entityID = entityResp.Data["id"].(string)
		log.Info("✅ Entity already exists", zap.String("entity_id", entityID))
	} else {
		// Create the entity
		entityData := map[string]interface{}{
			"name":     entityName,
			"metadata": map[string]interface{}{"purpose": "EOS CLI unified identity"},
			"policies": []string{shared.EosDefaultPolicyName},
		}
		resp, err := client.Logical().Write(shared.EosEntityPath, entityData)
		if err != nil {
			return fmt.Errorf("failed to create entity: %w", err)
		}
		entityID = resp.Data["id"].(string)
		log.Info("✅ Created new entity", zap.String("entity_id", entityID))
	}

	// Assign policies to the entity
	_, err = client.Logical().Write(fmt.Sprintf("%s/id/%s", shared.EosEntityPath, entityID), map[string]interface{}{
		"policies": []string{shared.EosDefaultPolicyName},
	})
	if err != nil {
		return fmt.Errorf("failed to assign policy to entity: %w", err)
	}
	log.Info("✅ Policy assigned to entity", zap.String("entity_id", entityID))

	// Add aliases for userpass and approle
	auths, err := client.Sys().ListAuth()
	if err != nil {
		log.Warn("⚠ Failed to list auth methods, skipping alias creation", zap.Error(err))
		return nil
	}
	for mount, label := range shared.AuthBackendLabels {
		if accessorInfo, ok := auths[mount]; ok {
			accessor := accessorInfo.Accessor
			aliasData := map[string]interface{}{
				"name":           entityName,
				"canonical_id":   entityID,
				"mount_accessor": accessor,
			}
			_, err = client.Logical().Write(shared.EosEntityAliasPath, aliasData)
			if err != nil {
				log.Warn(fmt.Sprintf("⚠ Failed to create %s alias", label), zap.Error(err))
			} else {
				log.Info(fmt.Sprintf("✅ Linked %s auth to entity", label))
			}
		} else {
			log.Info(fmt.Sprintf("ℹ %s auth not enabled yet, skipping alias", label))
		}
	}
	return nil
}

func ApplyEosPolicy(creds shared.UserpassCreds, client *api.Client) error {
	zap.L().Info("🔐 Creating full-access policy for eos user")
	zap.L().Debug("Applying policy to eos user", zap.Int("password_len", len(creds.Password)))

	policyName := shared.EosDefaultPolicyName
	policy, err := shared.RenderEosPolicy("users")
	if err != nil {
		return fmt.Errorf("failed to render policy: %w", err)
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
	if err := WriteKVv2(client, shared.VaultMountKV, shared.EosVaultUserPath, data); err != nil {
		zap.L().Error("❌ Failed to create eos user in Vault", zap.Error(err))
		return fmt.Errorf("failed to write eos user credentials: %w", err)
	}

	zap.L().Info("✅ eos user created and policy assigned", zap.String("user", shared.EosID), zap.String("policy", policyName))
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
	rolePath := shared.AppRolePath

	client, err := GetRootClient()
	if err != nil {
		log.Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	log.Info("🔑 Attaching eos-policy to eos-approle", zap.String("role_path", rolePath))

	data := map[string]interface{}{
		"policies": shared.EosDefaultPolicyName,
	}

	_, err = client.Logical().Write(rolePath, data)
	if err != nil {
		log.Error("❌ Failed to attach policy to AppRole", zap.Error(err))
		return fmt.Errorf("failed to attach eos-policy to eos-approle: %w", err)
	}

	log.Info("✅ eos-policy successfully attached to eos-approle", zap.String("policy", shared.EosDefaultPolicyName))
	return nil
}
