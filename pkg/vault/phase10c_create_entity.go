// pkg/vault/phase10c_create_entity.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func PhaseCreateEosEntity(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	entityName := shared.EosID

	log.Info("[Phase10c] Ensuring EOS entity and aliases exist")

	client, err := GetRootClient(rc)
	if err != nil {
		log.Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	// Check if entity exists
	entityLookupPath := fmt.Sprintf(shared.EosEntityLookupPath, entityName)
	entityResp, err := client.Logical().Read(entityLookupPath)
	var entityID string

	if err != nil {
		return fmt.Errorf("failed to look up entity: %w", err)
	}

	if entityResp != nil && entityResp.Data != nil {
		entityID = entityResp.Data["id"].(string)
		log.Info("✅ Entity already exists", zap.String("entity_id", entityID))
	} else {
		entityData := map[string]interface{}{
			"name":     entityName,
			"metadata": map[string]interface{}{"purpose": shared.EosEntityPurpose},
			"policies": []string{shared.EosDefaultPolicyName},
		}
		resp, err := client.Logical().Write(shared.EosEntityPath, entityData)
		if err != nil {
			return fmt.Errorf("failed to create entity: %w", err)
		}
		entityID = resp.Data["id"].(string)
		log.Info("✅ Created new entity", zap.String("entity_id", entityID))
	}

	// Add aliases if auth backends exist
	auths, err := client.Sys().ListAuth()
	if err != nil {
		log.Warn("⚠ Failed to list auth methods, skipping alias creation", zap.Error(err))
		return nil
	}

	for mount, label := range shared.AuthBackendLabels {
		if accessorInfo, ok := auths[mount]; ok {
			accessor := accessorInfo.Accessor
			aliasData := map[string]interface{}{
				"name":           shared.EosID,
				"canonical_id":   entityID,
				"mount_accessor": accessor,
			}
			_, err = client.Logical().Write(shared.EosEntityAliasPath, aliasData)
			if err != nil {
				log.Warn(fmt.Sprintf("⚠ Failed to create %s alias", label), zap.Error(err))
			} else {
				log.Info(fmt.Sprintf("✅ Linked %s to entity", label))
			}
		} else {
			log.Info(fmt.Sprintf("ℹ %s auth not enabled yet, skipping alias", label))
		}
	}

	return nil
}
