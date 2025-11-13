// pkg/vault/fix/mfa.go
// MFA enforcement policy repair operations

package fix

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BrokenMFAPolicy represents an MFA enforcement policy that is missing entity IDs
type BrokenMFAPolicy struct {
	Name string
	Path string
	Data map[string]interface{}
}

// RepairMFAEnforcement fixes MFA enforcement policies that are missing identity_entity_ids
//
// This function addresses the issue where MFA enforcement policies exist in Vault but don't
// apply to any users because the identity_entity_ids field is missing or empty. Without this
// field, Vault's safety default is to not enforce MFA on anyone.
//
// The function follows the Assess → Intervene → Evaluate pattern:
//
// ASSESS:
//   - List all MFA login enforcement policies
//   - Check each policy for missing or empty identity_entity_ids
//   - Lookup the eos entity ID to use for fixing
//
// INTERVENE:
//   - For each broken policy, add the entity ID to identity_entity_ids
//   - Update the policy in Vault
//
// EVALUATE:
//   - Re-read each fixed policy
//   - Verify identity_entity_ids is now present
//
// Returns:
//   - issuesFound: Number of policies missing entity IDs
//   - issuesFixed: Number of policies successfully fixed
//   - error: Non-nil if the operation failed critically
//
// Example usage:
//
//	found, fixed, err := RepairMFAEnforcement(rc, client, false)
//	if err != nil {
//	    return fmt.Errorf("MFA repair failed: %w", err)
//	}
//	fmt.Printf("Found %d issues, fixed %d\n", found, fixed)
func RepairMFAEnforcement(rc *eos_io.RuntimeContext, client *api.Client, dryRun bool) (int, int, error) {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS
	log.Info("[ASSESS] Checking MFA enforcement policies for missing entity IDs")

	brokenPolicies := []BrokenMFAPolicy{}

	// List all enforcement policies
	listResp, err := client.Logical().List("identity/mfa/login-enforcement")
	if err != nil {
		// Not a critical error - MFA might not be set up yet
		log.Debug("Cannot list MFA enforcement policies (MFA may not be configured)", zap.Error(err))
		return 0, 0, nil
	}

	if listResp == nil || listResp.Data == nil {
		log.Debug("No MFA enforcement policies found (MFA may not be configured)")
		return 0, 0, nil
	}

	keys, ok := listResp.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		log.Debug("No MFA enforcement policy keys found")
		return 0, 0, nil
	}

	log.Info(fmt.Sprintf("  Found %d MFA enforcement policy/policies to check", len(keys)))

	// Check each policy
	for _, keyInterface := range keys {
		policyName, ok := keyInterface.(string)
		if !ok {
			continue
		}

		policyPath := fmt.Sprintf("identity/mfa/login-enforcement/%s", policyName)

		policyResp, err := client.Logical().Read(policyPath)
		if err != nil {
			log.Warn(fmt.Sprintf("  Cannot read policy %s", policyName), zap.Error(err))
			continue
		}

		if policyResp == nil || policyResp.Data == nil {
			log.Warn(fmt.Sprintf("  Policy %s has no data", policyName))
			continue
		}

		// Check if entity IDs are missing or empty
		entityIDs, ok := policyResp.Data["identity_entity_ids"].([]interface{})
		if !ok || len(entityIDs) == 0 {
			// FOUND BROKEN POLICY
			log.Warn(fmt.Sprintf("  ⚠ Policy '%s' is missing entity IDs (not enforced on any users)", policyName))
			brokenPolicies = append(brokenPolicies, BrokenMFAPolicy{
				Name: policyName,
				Path: policyPath,
				Data: policyResp.Data,
			})
		} else {
			log.Info(fmt.Sprintf("  ✓ Policy '%s' has %d entity ID(s)", policyName, len(entityIDs)))
		}
	}

	if len(brokenPolicies) == 0 {
		log.Info("  ✓ All MFA enforcement policies have entity IDs - no fixes needed")
		return 0, 0, nil
	}

	log.Info(fmt.Sprintf("  Found %d broken MFA enforcement policy/policies", len(brokenPolicies)))
	for _, policy := range brokenPolicies {
		log.Info(fmt.Sprintf("    • %s", policy.Name))
	}

	// Lookup eos entity ID (needed to fix the policies)
	log.Info("  Looking up eos entity ID for fixing policies")
	entityID, err := lookupEosEntityID(rc, client)
	if err != nil {
		return len(brokenPolicies), 0, cerr.Wrap(err, "cannot fix MFA enforcement without entity ID")
	}
	log.Info(fmt.Sprintf("  ✓ Found eos entity ID: %s", entityID))

	if dryRun {
		log.Info("[DRY-RUN] Would add entity ID to enforcement policies",
			zap.String("entity_id", entityID),
			zap.Int("policies_to_fix", len(brokenPolicies)))
		log.Info("")
		log.Info("  The following policies would be updated:")
		for _, policy := range brokenPolicies {
			log.Info(fmt.Sprintf("    • %s", policy.Name))
			log.Info(fmt.Sprintf("      Current: No entity IDs"))
			log.Info(fmt.Sprintf("      After:   identity_entity_ids: [%s]", entityID))
		}
		log.Info("")
		log.Info("  Run without --dry-run to apply these changes")
		return len(brokenPolicies), 0, nil
	}

	// INTERVENE
	log.Info("[INTERVENE] Fixing MFA enforcement policies",
		zap.String("entity_id", entityID),
		zap.Int("policies_to_fix", len(brokenPolicies)))

	fixed := 0
	var fixErrors []error

	for _, policy := range brokenPolicies {
		log.Info(fmt.Sprintf("  Fixing policy: %s", policy.Name))

		// Add entity ID to existing config
		// CRITICAL: Must preserve existing config fields (mfa_method_ids, auth_method_accessors, etc.)
		policy.Data["identity_entity_ids"] = []string{entityID}

		_, err := client.Logical().Write(policy.Path, policy.Data)
		if err != nil {
			log.Error(fmt.Sprintf("  ✗ Failed to fix policy %s", policy.Name), zap.Error(err))
			fixErrors = append(fixErrors, cerr.Wrapf(err, "failed to fix policy %s", policy.Name))
			continue
		}

		log.Info(fmt.Sprintf("  ✓ Fixed policy: %s", policy.Name))
		fixed++
	}

	if len(fixErrors) > 0 {
		log.Warn("  Some policies could not be fixed",
			zap.Int("total", len(brokenPolicies)),
			zap.Int("fixed", fixed),
			zap.Int("failed", len(fixErrors)))
	}

	// EVALUATE
	log.Info("[EVALUATE] Verifying fixes")

	verified := 0
	for i, policy := range brokenPolicies {
		if i >= fixed {
			break // Don't verify policies that weren't fixed
		}

		verifyResp, err := client.Logical().Read(policy.Path)
		if err != nil {
			log.Warn(fmt.Sprintf("  ⚠ Cannot verify policy %s", policy.Name), zap.Error(err))
			continue
		}

		if verifyResp == nil || verifyResp.Data == nil {
			log.Warn(fmt.Sprintf("  ⚠ Policy %s verification returned no data", policy.Name))
			continue
		}

		entityIDs, ok := verifyResp.Data["identity_entity_ids"].([]interface{})
		if !ok || len(entityIDs) == 0 {
			log.Error(fmt.Sprintf("  ✗ Policy %s still missing entity IDs after fix!", policy.Name))
			continue
		}

		log.Info(fmt.Sprintf("  ✓ Verified: %s now targets %d entity/entities", policy.Name, len(entityIDs)))
		verified++
	}

	if verified == fixed {
		log.Info(fmt.Sprintf("  ✓ All %d fixed policies verified successfully", fixed))
	} else {
		log.Warn(fmt.Sprintf("  ⚠ Only %d of %d fixed policies could be verified", verified, fixed))
	}

	// Return errors if some fixes failed
	if len(fixErrors) > 0 {
		return len(brokenPolicies), fixed, cerr.Newf("failed to fix %d of %d policies", len(fixErrors), len(brokenPolicies))
	}

	return len(brokenPolicies), fixed, nil
}

// lookupEosEntityID retrieves the entity ID for the "eos" user
//
// This function is used by RepairMFAEnforcement to determine which entity ID
// should be added to the MFA enforcement policy.
//
// It follows the same lookup pattern as VerifyAndFetchMFAPrerequisites:
//  1. Try to lookup entity by name "eos"
//  2. If not found by name, try to lookup by userpass alias
//  3. Return error if entity cannot be found
//
// Returns:
//   - entityID: The Vault entity ID (UUID)
//   - error: Non-nil if entity lookup failed
func lookupEosEntityID(rc *eos_io.RuntimeContext, client *api.Client) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	username := shared.EosID // "eos"

	// Try to lookup entity by name
	entityLookupPath := fmt.Sprintf(shared.EosEntityLookupPath, username)
	entityResp, err := client.Logical().Read(entityLookupPath)

	if err == nil && entityResp != nil && entityResp.Data != nil {
		if entityID, ok := entityResp.Data["id"].(string); ok && entityID != "" {
			log.Debug("Found entity by name lookup",
				zap.String("username", username),
				zap.String("entity_id", entityID))
			return entityID, nil
		}
	}

	// Fallback: Try to lookup entity via userpass alias
	// List all entities and find one with userpass alias matching username
	log.Debug("Entity name lookup failed, trying alias lookup",
		zap.String("username", username))

	// Get userpass mount accessor
	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", cerr.Wrap(err, "failed to list auth mounts for entity lookup")
	}

	var userpassAccessor string
	for path, mount := range authMounts {
		if mount.Type == "userpass" || strings.HasPrefix(path, "userpass") {
			userpassAccessor = mount.Accessor
			break
		}
	}

	if userpassAccessor == "" {
		return "", cerr.New("userpass auth method not found - cannot lookup entity")
	}

	// Query entity by alias name
	aliasLookupPath := "identity/lookup/entity"
	aliasLookupData := map[string]interface{}{
		"alias_name":           username,
		"alias_mount_accessor": userpassAccessor,
	}

	aliasResp, err := client.Logical().Write(aliasLookupPath, aliasLookupData)
	if err != nil {
		return "", cerr.Wrap(err, "failed to lookup entity by alias")
	}

	if aliasResp == nil || aliasResp.Data == nil {
		return "", cerr.Newf("entity for user %s not found (neither by name nor alias)", username)
	}

	entityID, ok := aliasResp.Data["id"].(string)
	if !ok || entityID == "" {
		return "", cerr.New("entity ID not found in alias lookup response")
	}

	log.Debug("Found entity by alias lookup",
		zap.String("username", username),
		zap.String("entity_id", entityID),
		zap.String("userpass_accessor", userpassAccessor))

	return entityID, nil
}
