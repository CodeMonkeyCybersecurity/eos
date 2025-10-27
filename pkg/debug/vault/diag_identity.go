// pkg/debug/vault/diag_identity.go
// Identity entity and alias diagnostics for Vault

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
)

// IdentityDiagnostic checks the Vault Identity entity and aliases for the EOS user
// This diagnostic verifies:
// - Entity exists and has correct configuration
// - Entity aliases are created for all enabled auth backends
// - MFA methods are properly associated (if configured)
//
// Use cases:
// - Troubleshooting TOTP MFA setup failures (missing entity ID)
// - Verifying multi-auth backend configuration
// - Debugging authentication issues across different auth methods
func IdentityDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Identity Entity and Aliases",
		Category:    "identity",
		Description: "Check Vault Identity entity and aliases for EOS user",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Name:   "Identity Entity and Aliases",
				Status: debug.StatusOK,
			}

			// Create runtime context from the diagnostic context
			// The context passed to diagnostics contains the parent runtime context's Ctx
			rc := &eos_io.RuntimeContext{Ctx: ctx}

			// Use admin client for debug operations (HashiCorp best practice)
			client, err := vault.GetAdminClient(rc)
			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Failed to get admin Vault client"
				result.Output = fmt.Sprintf("Error: %v\n\nEnsure Vault is running and you have admin access", err)
				result.Remediation = "Run 'eos debug vault --auth' to diagnose authentication issues"
				return result, nil
			}

			// ASSESS: Look up the EOS entity by name
			entityName := shared.EosID
			entityLookupPath := fmt.Sprintf(shared.EosEntityLookupPath, entityName)

			entityResp, err := client.Logical().Read(entityLookupPath)
			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Failed to look up EOS entity"
				result.Output = fmt.Sprintf("Entity lookup path: %s\nError: %v", entityLookupPath, err)
				result.Remediation = "This may indicate Vault Identity system is not accessible. Check Vault health."
				return result, nil
			}

			if entityResp == nil || entityResp.Data == nil {
				result.Status = debug.StatusError
				result.Message = "EOS entity does not exist"
				result.Output = fmt.Sprintf("Entity name: %s\nLookup path: %s\n\nEntity should have been created during 'eos create vault'", entityName, entityLookupPath)
				result.Remediation = "Run 'eos create vault' to recreate the entity, or check Vault logs for entity creation failures"
				return result, nil
			}

			// Entity exists - extract details
			entityID, ok := entityResp.Data["id"].(string)
			if !ok || entityID == "" {
				result.Status = debug.StatusError
				result.Message = "Entity ID is missing or invalid"
				result.Output = fmt.Sprintf("Entity response: %+v", entityResp.Data)
				return result, nil
			}

			// Extract entity metadata
			var entityInfo strings.Builder
			entityInfo.WriteString(fmt.Sprintf("Entity ID: %s\n", entityID))
			entityInfo.WriteString(fmt.Sprintf("Entity Name: %s\n", entityName))

			// Metadata
			if metadata, ok := entityResp.Data["metadata"].(map[string]interface{}); ok && len(metadata) > 0 {
				entityInfo.WriteString("\nMetadata:\n")
				for key, value := range metadata {
					entityInfo.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
				}
			}

			// Policies
			if policies, ok := entityResp.Data["policies"].([]interface{}); ok && len(policies) > 0 {
				entityInfo.WriteString("\nPolicies:\n")
				for _, policy := range policies {
					entityInfo.WriteString(fmt.Sprintf("  - %v\n", policy))
				}
			} else {
				entityInfo.WriteString("\nPolicies: (none)\n")
			}

			// Check aliases
			aliasesInfo, aliasWarnings := checkEntityAliases(client, entityResp.Data)
			entityInfo.WriteString(aliasesInfo)

			// Check MFA methods
			mfaInfo := checkMFAMethods(client)
			if mfaInfo != "" {
				entityInfo.WriteString(mfaInfo)
			}

			// Set result status based on findings
			if len(aliasWarnings) > 0 {
				result.Status = debug.StatusWarning
				result.Message = "Entity exists but has alias issues"
				result.Output = entityInfo.String()
				result.Remediation = strings.Join(aliasWarnings, "\n")
			} else {
				result.Status = debug.StatusOK
				result.Message = "EOS entity configured correctly"
				result.Output = entityInfo.String()
			}

			return result, nil
		},
	}
}

// checkEntityAliases examines entity aliases and validates them against enabled auth backends
func checkEntityAliases(client *api.Client, entityData map[string]interface{}) (string, []string) {
	var info strings.Builder
	var warnings []string

	info.WriteString("\nEntity Aliases:\n")

	// Get aliases from entity data
	aliases, ok := entityData["aliases"].([]interface{})
	if !ok || len(aliases) == 0 {
		info.WriteString("  (no aliases configured)\n")
		warnings = append(warnings, "No entity aliases found - authentication may not work correctly")
		return info.String(), warnings
	}

	// Get enabled auth backends for validation
	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		info.WriteString(fmt.Sprintf("  Unable to list auth backends: %v\n", err))
		warnings = append(warnings, "Cannot validate aliases against auth backends")
		return info.String(), warnings
	}

	// Track which auth backends have aliases
	authBackendsWithAliases := make(map[string]bool)

	// Display each alias
	for i, aliasInterface := range aliases {
		alias, ok := aliasInterface.(map[string]interface{})
		if !ok {
			info.WriteString(fmt.Sprintf("  Alias %d: Invalid format\n", i+1))
			continue
		}

		aliasID := getStringValue(alias, "id")
		aliasName := getStringValue(alias, "name")
		mountAccessor := getStringValue(alias, "mount_accessor")

		info.WriteString(fmt.Sprintf("\nAlias %d:\n", i+1))
		info.WriteString(fmt.Sprintf("  ID: %s\n", aliasID))
		info.WriteString(fmt.Sprintf("  Name: %s\n", aliasName))
		info.WriteString(fmt.Sprintf("  Mount Accessor: %s\n", mountAccessor))

		// Find which auth backend this alias belongs to
		var mountPath string
		var mountType string
		for path, mount := range authMounts {
			if mount.Accessor == mountAccessor {
				mountPath = path
				mountType = mount.Type
				authBackendsWithAliases[path] = true
				break
			}
		}

		if mountPath != "" {
			info.WriteString(fmt.Sprintf("  Mount Path: %s\n", mountPath))
			info.WriteString(fmt.Sprintf("  Auth Type: %s\n", mountType))
		} else {
			info.WriteString("  Mount Path: (unknown - accessor not found)\n")
			warnings = append(warnings, fmt.Sprintf("Alias %d has invalid mount accessor %s", i+1, mountAccessor))
		}
	}

	// Check for missing aliases (auth backends without aliases)
	expectedBackends := map[string]bool{
		shared.AuthBackendUserpass: true,
		shared.AuthBackendApprole:  true,
	}

	for expectedBackend := range expectedBackends {
		if _, exists := authMounts[expectedBackend]; exists {
			if !authBackendsWithAliases[expectedBackend] {
				warnings = append(warnings, fmt.Sprintf("Auth backend '%s' is enabled but has no entity alias", expectedBackend))
			}
		}
	}

	return info.String(), warnings
}

// checkMFAMethods retrieves information about configured MFA methods
func checkMFAMethods(client *api.Client) string {
	var info strings.Builder

	// Try to read TOTP method configuration from Vault KV
	methodIDSecret, err := client.Logical().Read("secret/data/eos/mfa-methods/totp")
	if err != nil {
		// MFA not configured - this is OK
		return ""
	}

	if methodIDSecret == nil || methodIDSecret.Data == nil {
		return ""
	}

	data, ok := methodIDSecret.Data["data"].(map[string]interface{})
	if !ok {
		return ""
	}

	methodID := getStringValue(data, "method_id")
	if methodID == "" {
		return ""
	}

	info.WriteString("\nMFA Methods:\n")
	info.WriteString("  TOTP: Enabled\n")
	info.WriteString(fmt.Sprintf("  Method ID: %s\n", methodID))

	// Get additional TOTP method details if available
	if createdAt := getStringValue(data, "created_at"); createdAt != "" {
		info.WriteString(fmt.Sprintf("  Created: %s\n", createdAt))
	}

	return info.String()
}

// getStringValue safely extracts a string value from a map[string]interface{}
func getStringValue(data map[string]interface{}, key string) string {
	if val, ok := data[key].(string); ok {
		return val
	}
	return ""
}
