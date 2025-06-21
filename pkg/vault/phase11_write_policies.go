package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func EnsurePolicy(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info("📝 Preparing to write all Vault policies")

	client, err := GetRootClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	// Create all role-based policies using programmatic builders
	policies := []struct {
		name    string
		builder func(*eos_io.RuntimeContext) (string, error)
	}{
		{shared.EosDefaultPolicyName, BuildEosDefaultPolicy},
		{shared.EosAdminPolicyName, BuildEosAdminPolicy},
		{shared.EosEmergencyPolicyName, BuildEosEmergencyPolicy},
		{shared.EosReadOnlyPolicyName, BuildEosReadOnlyPolicy},
	}

	for _, policy := range policies {
		otelzap.Ctx(rc.Ctx).Info("📝 Writing Vault policy", zap.String("policy", policy.name))

		pol, err := policy.builder(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("❌ Failed to build policy", zap.String("policy", policy.name), zap.Error(err))
			return fmt.Errorf("build policy %s: %w", policy.name, err)
		}

		// Validate and fix common HCL issues
		fixedPolicy, err := ValidateAndFixCommonIssues(rc, policy.name, pol)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("❌ Policy validation failed",
				zap.String("policy", policy.name),
				zap.Error(err))
			return fmt.Errorf("policy validation failed for %s: %w", policy.name, err)
		} else if fixedPolicy != pol {
			otelzap.Ctx(rc.Ctx).Info("🔧 Policy automatically fixed",
				zap.String("policy", policy.name))
			pol = fixedPolicy
		}

		otelzap.Ctx(rc.Ctx).Debug("📄 Policy loaded", zap.String("policy", policy.name), zap.String("preview", truncatePolicy(pol)), zap.Int("length", len(pol)))

		otelzap.Ctx(rc.Ctx).Info("📡 Writing policy to Vault", zap.String("policy", policy.name))
		if err := client.Sys().PutPolicy(policy.name, pol); err != nil {
			otelzap.Ctx(rc.Ctx).Error("❌ Failed to write policy", zap.String("policy", policy.name), zap.Error(err))
			return fmt.Errorf("failed to write policy %s to Vault: %w", policy.name, err)
		}

		otelzap.Ctx(rc.Ctx).Info("🔍 Verifying policy write", zap.String("policy", policy.name))
		storedPol, err := client.Sys().GetPolicy(policy.name)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("❌ Failed to retrieve policy for verification", zap.String("policy", policy.name), zap.Error(err))
			return fmt.Errorf("failed to verify written policy %s: %w", policy.name, err)
		}
		if strings.TrimSpace(storedPol) != strings.TrimSpace(pol) {
			otelzap.Ctx(rc.Ctx).Error("🚨 Policy mismatch after write",
				zap.String("policy", policy.name),
				zap.String("expected_preview", truncatePolicy(pol)),
				zap.String("stored_preview", truncatePolicy(storedPol)))
			return fmt.Errorf("policy mismatch after write for %s — vault contents are inconsistent", policy.name)
		}

		otelzap.Ctx(rc.Ctx).Info("✅ Policy successfully written and verified", zap.String("policy", policy.name))
	}

	if err := AttachPolicyToEosEntity(rc, client, rc.Log); err != nil {
		return fmt.Errorf("failed to attach eos-policy to eos entity: %w", err)
	}

	return nil
}

func AttachPolicyToEosEntity(rc *eos_io.RuntimeContext, client *api.Client, log *zap.Logger) error {
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
			"metadata": map[string]interface{}{"purpose": "Eos CLI unified identity"},
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

func ApplyEosPolicy(rc *eos_io.RuntimeContext, creds shared.UserpassCreds, client *api.Client) error {
	otelzap.Ctx(rc.Ctx).Info("🔐 Creating full-access policy for eos user")
	otelzap.Ctx(rc.Ctx).Debug("Applying policy to eos user", zap.Int("password_len", len(creds.Password)))

	policyName := shared.EosDefaultPolicyName
	policy, err := shared.RenderEosPolicy("users")
	if err != nil {
		return fmt.Errorf("failed to render policy: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info("📜 Uploading custom policy to Vault", zap.String("policy", policyName))
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to apply policy via API", zap.Error(err))
		return fmt.Errorf("failed to upload policy %q: %w", policyName, err)
	}
	otelzap.Ctx(rc.Ctx).Info("✅ Policy applied to Vault", zap.String("policy", policyName))

	otelzap.Ctx(rc.Ctx).Info("🔑 Creating eos user in KVv2")
	data := map[string]interface{}{
		"password": creds.Password,
		"policies": policyName,
	}
	if err := WriteKVv2(rc, client, shared.VaultMountKV, shared.EosVaultUserPath, data); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to create eos user in Vault", zap.Error(err))
		return fmt.Errorf("failed to write eos user credentials: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info("✅ eos user created and policy assigned", zap.String("user", shared.EosID), zap.String("policy", policyName))
	return nil
}

func truncatePolicy(policy string) string {
	policy = strings.TrimSpace(policy)
	if len(policy) > 100 {
		return policy[:100] + "..."
	}
	return policy
}
