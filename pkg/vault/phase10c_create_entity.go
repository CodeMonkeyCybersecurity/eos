// pkg/vault/phase10c_create_entity.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func PhaseCreateEosEntity(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	entityName := shared.EosID

	log.Info("[Phase10c] Ensuring Eos entity and aliases exist")

	client, err := GetPrivilegedClient(rc)
	if err != nil {
		log.Error(" Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("get privileged vault client: %w", err)
	}

	// ASSESS: Check if entity exists
	entityLookupPath := fmt.Sprintf(shared.EosEntityLookupPath, entityName)
	log.Info(" [ASSESS] Looking up existing entity",
		zap.String("entity_name", entityName),
		zap.String("lookup_path", entityLookupPath))

	entityResp, err := client.Logical().Read(entityLookupPath)
	var entityID string

	if err != nil {
		log.Error(" [ASSESS] Failed to look up entity",
			zap.Error(err),
			zap.String("path", entityLookupPath))
		return fmt.Errorf("failed to look up entity: %w", err)
	}

	if entityResp != nil && entityResp.Data != nil {
		// Entity exists
		entityID = entityResp.Data["id"].(string)
		log.Info(" [EVALUATE] Entity already exists",
			zap.String("entity_id", entityID),
			zap.String("entity_name", entityName),
			zap.Any("metadata", entityResp.Data["metadata"]),
			zap.Any("policies", entityResp.Data["policies"]))

		// Log additional entity details for diagnostics
		if aliases, ok := entityResp.Data["aliases"]; ok {
			log.Debug("Existing entity has aliases", zap.Any("aliases", aliases))
		}
	} else {
		// Entity doesn't exist - create it
		log.Info(" [INTERVENE] Creating new entity",
			zap.String("entity_name", entityName),
			zap.String("policy", shared.EosDefaultPolicyName),
			zap.String("purpose", shared.EosEntityPurpose))

		entityData := map[string]interface{}{
			"name":     entityName,
			"metadata": map[string]interface{}{"purpose": shared.EosEntityPurpose},
			"policies": []string{shared.EosDefaultPolicyName},
		}

		log.Debug("Entity creation data", zap.Any("data", entityData))

		resp, err := client.Logical().Write(shared.EosEntityPath, entityData)
		if err != nil {
			log.Error(" [EVALUATE] Failed to create entity",
				zap.Error(err),
				zap.String("path", shared.EosEntityPath),
				zap.Any("entity_data", entityData))
			return fmt.Errorf("failed to create entity: %w", err)
		}

		if resp == nil || resp.Data == nil {
			log.Error(" [EVALUATE] Entity creation returned nil response")
			return fmt.Errorf("entity creation returned nil response")
		}

		entityID = resp.Data["id"].(string)
		log.Info(" [EVALUATE] Entity created successfully",
			zap.String("entity_id", entityID),
			zap.String("entity_name", entityName))

		// Verify entity was created by reading it back
		log.Info(" Verifying entity creation")
		verifyResp, verifyErr := client.Logical().Read(entityLookupPath)
		if verifyErr != nil {
			log.Warn("Failed to verify entity creation", zap.Error(verifyErr))
		} else if verifyResp == nil {
			log.Warn("Entity verification returned nil - entity may not have been created properly")
		} else {
			log.Info(" Entity verification successful",
				zap.String("entity_id", verifyResp.Data["id"].(string)),
				zap.Any("policies", verifyResp.Data["policies"]))
		}
	}

	// ASSESS: List available auth backends for alias creation
	log.Info(" [ASSESS] Listing available auth backends for alias creation")
	auths, err := client.Sys().ListAuth()
	if err != nil {
		log.Error(" Failed to list auth methods, cannot create aliases",
			zap.Error(err))
		return fmt.Errorf("list auth methods: %w", err)
	}

	log.Info(" Auth backends discovered",
		zap.Int("count", len(auths)),
		zap.Any("backends", getAuthBackendSummary(auths)))

	// INTERVENE: Create aliases for each auth backend
	aliasesCreated := 0
	aliasesSkipped := 0
	aliasesFailed := 0

	for mount, label := range shared.AuthBackendLabels {
		if accessorInfo, ok := auths[mount]; ok {
			accessor := accessorInfo.Accessor
			log.Info(fmt.Sprintf(" [INTERVENE] Creating %s alias", label),
				zap.String("mount", mount),
				zap.String("accessor", accessor),
				zap.String("entity_id", entityID))

			aliasData := map[string]interface{}{
				"name":           shared.EosID,
				"canonical_id":   entityID,
				"mount_accessor": accessor,
			}

			aliasResp, err := client.Logical().Write(shared.EosEntityAliasPath, aliasData)
			if err != nil {
				log.Error(fmt.Sprintf(" [EVALUATE] Failed to create %s alias", label),
					zap.Error(err),
					zap.String("mount", mount),
					zap.String("accessor", accessor),
					zap.String("error_detail", err.Error()))
				aliasesFailed++
			} else {
				aliasID := ""
				if aliasResp != nil && aliasResp.Data != nil {
					if id, ok := aliasResp.Data["id"].(string); ok {
						aliasID = id
					}
				}
				log.Info(fmt.Sprintf(" [EVALUATE] %s alias created successfully", label),
					zap.String("mount", mount),
					zap.String("alias_id", aliasID),
					zap.String("entity_id", entityID))
				aliasesCreated++
			}
		} else {
			log.Info(fmt.Sprintf(" [ASSESS] %s auth not enabled, skipping alias", label),
				zap.String("mount", mount),
				zap.String("label", label))
			aliasesSkipped++
		}
	}

	// EVALUATE: Summary of alias creation
	log.Info(" [EVALUATE] Entity alias creation complete",
		zap.String("entity_id", entityID),
		zap.Int("created", aliasesCreated),
		zap.Int("skipped", aliasesSkipped),
		zap.Int("failed", aliasesFailed))

	if aliasesFailed > 0 {
		log.Warn("Some aliases failed to create - entity may not be fully configured",
			zap.Int("failed_count", aliasesFailed))
	}

	return nil
}

// getAuthBackendSummary creates a summary of auth backends for logging
func getAuthBackendSummary(auths map[string]*api.AuthMount) map[string]string {
	summary := make(map[string]string)
	for path, mount := range auths {
		summary[path] = fmt.Sprintf("type=%s, accessor=%s", mount.Type, mount.Accessor)
	}
	return summary
}
