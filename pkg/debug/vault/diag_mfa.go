// pkg/debug/vault/diag_mfa.go
// MFA enforcement diagnostics for Vault
// This diagnostic helps troubleshoot MFA enforcement verification failures
// by comprehensively checking the state of MFA configuration, enforcement policies,
// and entity/method linkages.

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

// MFAEnforcementDiagnostic performs comprehensive MFA enforcement diagnostics
// This diagnostic verifies:
// - MFA methods are created and configured correctly
// - Enforcement policies exist and have correct structure
// - Entity is properly linked to MFA methods
// - Authentication with MFA can be tested (optional)
//
// Use cases:
// - Troubleshooting "expected MFA challenge but got direct authentication" errors
// - Verifying MFA enforcement configuration before deployment
// - Debugging why MFA is not being enforced for authentication
func MFAEnforcementDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "MFA Enforcement Configuration",
		Category:    "mfa",
		Description: "Comprehensive check of MFA enforcement policies and configuration",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Name:   "MFA Enforcement Configuration",
				Status: debug.StatusOK,
			}

			var output strings.Builder
			var warnings []string
			var errors []string

			// Create runtime context
			rc := &eos_io.RuntimeContext{Ctx: ctx}

			// Get privileged client
			client, err := vault.GetPrivilegedClient(rc)
			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Failed to get privileged Vault client"
				result.Output = fmt.Sprintf("Error: %v\n\nEnsure Vault is initialized and root token is available", err)
				result.Remediation = "Run 'eos debug vault --auth' to diagnose authentication issues"
				return result, nil
			}

			output.WriteString("═══════════════════════════════════════════════════════════\n")
			output.WriteString("  MFA ENFORCEMENT DIAGNOSTIC REPORT\n")
			output.WriteString("═══════════════════════════════════════════════════════════\n\n")

			// Step 1: Check Vault version
			output.WriteString("Step 1: Vault Version\n")
			output.WriteString("─────────────────────────────────────────────────────────\n")
			versionInfo := checkVaultVersion(client)
			output.WriteString(versionInfo)
			output.WriteString("\n\n")

			// Step 2: Check MFA methods
			output.WriteString("Step 2: MFA Methods Configuration\n")
			output.WriteString("─────────────────────────────────────────────────────────\n")
			methodsInfo, methodsWarnings, methodsErrors := checkMFAMethodsDetailed(rc, client)
			output.WriteString(methodsInfo)
			warnings = append(warnings, methodsWarnings...)
			errors = append(errors, methodsErrors...)
			output.WriteString("\n\n")

			// Step 3: Check enforcement policies
			output.WriteString("Step 3: MFA Enforcement Policies\n")
			output.WriteString("─────────────────────────────────────────────────────────\n")
			enforcementInfo, enforcementWarnings, enforcementErrors := checkMFAEnforcementPolicies(rc, client)
			output.WriteString(enforcementInfo)
			warnings = append(warnings, enforcementWarnings...)
			errors = append(errors, enforcementErrors...)
			output.WriteString("\n\n")

			// Step 4: Check entity MFA linkage
			output.WriteString("Step 4: Entity MFA Linkage\n")
			output.WriteString("─────────────────────────────────────────────────────────\n")
			linkageInfo, linkageWarnings, linkageErrors := checkEntityMFALinkage(rc, client)
			output.WriteString(linkageInfo)
			warnings = append(warnings, linkageWarnings...)
			errors = append(errors, linkageErrors...)
			output.WriteString("\n\n")

			// Step 5: Check auth method accessors
			output.WriteString("Step 5: Auth Method Accessors\n")
			output.WriteString("─────────────────────────────────────────────────────────\n")
			accessorInfo := checkAuthAccessors(client)
			output.WriteString(accessorInfo)
			output.WriteString("\n\n")

			// Summary
			output.WriteString("═══════════════════════════════════════════════════════════\n")
			output.WriteString("  DIAGNOSTIC SUMMARY\n")
			output.WriteString("═══════════════════════════════════════════════════════════\n\n")

			if len(errors) > 0 {
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("MFA enforcement has %d critical errors", len(errors))
				output.WriteString(fmt.Sprintf("✗ Errors: %d\n", len(errors)))
				for i, errMsg := range errors {
					output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, errMsg))
				}
			} else if len(warnings) > 0 {
				result.Status = debug.StatusWarning
				result.Message = fmt.Sprintf("MFA enforcement has %d warnings", len(warnings))
				output.WriteString(fmt.Sprintf("⚠ Warnings: %d\n", len(warnings)))
				for i, warnMsg := range warnings {
					output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, warnMsg))
				}
			} else {
				result.Status = debug.StatusOK
				result.Message = "MFA enforcement is correctly configured"
				output.WriteString("✓ No issues detected\n")
			}

			result.Output = output.String()

			if len(errors) > 0 || len(warnings) > 0 {
				var remediation strings.Builder
				remediation.WriteString("Recommended actions:\n\n")

				if len(errors) > 0 {
					remediation.WriteString("Critical errors detected:\n")
					for _, errMsg := range errors {
						remediation.WriteString(fmt.Sprintf("  • %s\n", errMsg))
					}
					remediation.WriteString("\n")
				}

				if len(warnings) > 0 {
					remediation.WriteString("Warnings to address:\n")
					for _, warnMsg := range warnings {
						remediation.WriteString(fmt.Sprintf("  • %s\n", warnMsg))
					}
					remediation.WriteString("\n")
				}

				remediation.WriteString("To retry MFA setup:\n")
				remediation.WriteString("  1. Fix the issues listed above\n")
				remediation.WriteString("  2. Run: eos update vault --setup-mfa-user eos\n")
				remediation.WriteString("  3. Run this diagnostic again to verify\n")

				result.Remediation = remediation.String()
			}

			return result, nil
		},
	}
}

// checkVaultVersion retrieves Vault version information
func checkVaultVersion(client *api.Client) string {
	var info strings.Builder

	healthResp, err := client.Sys().Health()
	if err != nil {
		info.WriteString(fmt.Sprintf("  Unable to get Vault version: %v\n", err))
		return info.String()
	}

	info.WriteString(fmt.Sprintf("  Vault Version: %s\n", healthResp.Version))
	info.WriteString(fmt.Sprintf("  Initialized: %t\n", healthResp.Initialized))
	info.WriteString(fmt.Sprintf("  Sealed: %t\n", healthResp.Sealed))
	info.WriteString(fmt.Sprintf("  Cluster ID: %s\n", healthResp.ClusterID))

	return info.String()
}

// checkMFAMethodsDetailed checks MFA methods configuration in detail
func checkMFAMethodsDetailed(rc *eos_io.RuntimeContext, client *api.Client) (string, []string, []string) {
	var info strings.Builder
	var warnings []string
	var errors []string

	// Check TOTP method in KV
	methodIDSecret, err := client.Logical().Read("secret/data/eos/mfa-methods/totp")
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to read TOTP method from KV: %v", err))
		info.WriteString("  ✗ TOTP Method: Not found in KV\n")
		info.WriteString(fmt.Sprintf("    Error: %v\n", err))
		return info.String(), warnings, errors
	}

	if methodIDSecret == nil || methodIDSecret.Data == nil {
		warnings = append(warnings, "TOTP method not configured - MFA may not be enabled")
		info.WriteString("  ⚠ TOTP Method: Not configured\n")
		info.WriteString("    Run 'eos create vault' to set up MFA\n")
		return info.String(), warnings, errors
	}

	data, ok := methodIDSecret.Data["data"].(map[string]interface{})
	if !ok {
		errors = append(errors, "TOTP method data structure is invalid")
		info.WriteString("  ✗ TOTP Method: Invalid data structure\n")
		return info.String(), warnings, errors
	}

	methodID := getStringValue(data, "method_id")
	if methodID == "" {
		errors = append(errors, "TOTP method_id is missing or empty")
		info.WriteString("  ✗ TOTP Method: Missing method_id\n")
		return info.String(), warnings, errors
	}

	info.WriteString("  ✓ TOTP Method: Found in KV\n")
	info.WriteString(fmt.Sprintf("    Method ID: %s\n", methodID))

	if createdAt := getStringValue(data, "created_at"); createdAt != "" {
		info.WriteString(fmt.Sprintf("    Created: %s\n", createdAt))
	}

	// Try to read the actual method configuration from Vault
	methodPath := fmt.Sprintf("identity/mfa/method/totp/%s", methodID)
	methodResp, err := client.Logical().Read(methodPath)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Cannot read TOTP method details: %v", err))
		info.WriteString(fmt.Sprintf("  ⚠ Method details: %v\n", err))
	} else if methodResp == nil {
		warnings = append(warnings, "TOTP method ID exists in KV but not found in Vault identity system")
		info.WriteString("  ⚠ Method not found in identity system (may be deleted)\n")
	} else {
		info.WriteString("  ✓ Method verified in identity system\n")
		if methodResp.Data != nil {
			if issuer, ok := methodResp.Data["issuer"].(string); ok {
				info.WriteString(fmt.Sprintf("    Issuer: %s\n", issuer))
			}
			if algorithm, ok := methodResp.Data["algorithm"].(string); ok {
				info.WriteString(fmt.Sprintf("    Algorithm: %s\n", algorithm))
			}
			if digits, ok := methodResp.Data["digits"].(float64); ok {
				info.WriteString(fmt.Sprintf("    Digits: %.0f\n", digits))
			}
			if period, ok := methodResp.Data["period"].(float64); ok {
				info.WriteString(fmt.Sprintf("    Period: %.0fs\n", period))
			}
		}
	}

	return info.String(), warnings, errors
}

// checkMFAEnforcementPolicies checks MFA login enforcement policies
func checkMFAEnforcementPolicies(rc *eos_io.RuntimeContext, client *api.Client) (string, []string, []string) {
	var info strings.Builder
	var warnings []string
	var errors []string

	// List all login enforcement policies
	listResp, err := client.Logical().List("identity/mfa/login-enforcement")
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to list enforcement policies: %v", err))
		info.WriteString(fmt.Sprintf("  ✗ Cannot list policies: %v\n", err))
		return info.String(), warnings, errors
	}

	if listResp == nil || listResp.Data == nil {
		warnings = append(warnings, "No MFA enforcement policies found - MFA is not being enforced")
		info.WriteString("  ⚠ No enforcement policies configured\n")
		info.WriteString("    MFA methods exist but are not enforced for authentication\n")
		return info.String(), warnings, errors
	}

	keys, ok := listResp.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		warnings = append(warnings, "No MFA enforcement policies found")
		info.WriteString("  ⚠ No enforcement policies\n")
		return info.String(), warnings, errors
	}

	info.WriteString(fmt.Sprintf("  Found %d enforcement policy/policies:\n\n", len(keys)))

	// Check each policy
	for i, keyInterface := range keys {
		policyName, ok := keyInterface.(string)
		if !ok {
			continue
		}

		info.WriteString(fmt.Sprintf("  Policy %d: %s\n", i+1, policyName))

		policyPath := fmt.Sprintf("identity/mfa/login-enforcement/%s", policyName)
		policyResp, err := client.Logical().Read(policyPath)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to read policy '%s': %v", policyName, err))
			info.WriteString(fmt.Sprintf("    ✗ Cannot read policy: %v\n", err))
			continue
		}

		if policyResp == nil || policyResp.Data == nil {
			errors = append(errors, fmt.Sprintf("Policy '%s' has no data", policyName))
			info.WriteString("    ✗ No policy data\n")
			continue
		}

		// Check mfa_method_ids
		if methodIDs, ok := policyResp.Data["mfa_method_ids"].([]interface{}); ok {
			if len(methodIDs) == 0 {
				errors = append(errors, fmt.Sprintf("Policy '%s' has no MFA methods", policyName))
				info.WriteString("    ✗ No MFA methods specified\n")
			} else {
				info.WriteString(fmt.Sprintf("    ✓ MFA Methods: %d method(s)\n", len(methodIDs)))
				for j, methodID := range methodIDs {
					info.WriteString(fmt.Sprintf("      %d. %v\n", j+1, methodID))
				}
			}
		} else {
			errors = append(errors, fmt.Sprintf("Policy '%s' missing mfa_method_ids", policyName))
			info.WriteString("    ✗ Missing mfa_method_ids field\n")
		}

		// Check auth_method_accessors
		if accessors, ok := policyResp.Data["auth_method_accessors"].([]interface{}); ok {
			if len(accessors) == 0 {
				errors = append(errors, fmt.Sprintf("Policy '%s' has no auth method accessors", policyName))
				info.WriteString("    ✗ No auth method accessors\n")
			} else {
				info.WriteString(fmt.Sprintf("    ✓ Auth Accessors: %d accessor(s)\n", len(accessors)))
				for j, accessor := range accessors {
					info.WriteString(fmt.Sprintf("      %d. %v\n", j+1, accessor))
				}
			}
		} else {
			errors = append(errors, fmt.Sprintf("Policy '%s' missing auth_method_accessors", policyName))
			info.WriteString("    ✗ Missing auth_method_accessors field\n")
		}

		// Check identity_entity_ids (optional but may be required for enforcement to work)
		if entityIDs, ok := policyResp.Data["identity_entity_ids"].([]interface{}); ok {
			if len(entityIDs) > 0 {
				info.WriteString(fmt.Sprintf("    ✓ Entity IDs: %d entity/entities\n", len(entityIDs)))
				for j, entityID := range entityIDs {
					info.WriteString(fmt.Sprintf("      %d. %v\n", j+1, entityID))
				}
			} else {
				warnings = append(warnings, fmt.Sprintf("Policy '%s' has no entity IDs - may not apply to any users", policyName))
				info.WriteString("    ⚠ No entity IDs specified\n")
				info.WriteString("      This may cause enforcement to not apply to any users\n")
			}
		} else {
			// identity_entity_ids field doesn't exist
			warnings = append(warnings, fmt.Sprintf("Policy '%s' has no identity_entity_ids field - enforcement scope unclear", policyName))
			info.WriteString("    ⚠ No identity_entity_ids field\n")
			info.WriteString("      Enforcement may apply to all users or no users (Vault version dependent)\n")
		}

		// Check identity_group_ids
		if groupIDs, ok := policyResp.Data["identity_group_ids"].([]interface{}); ok {
			if len(groupIDs) > 0 {
				info.WriteString(fmt.Sprintf("    ✓ Group IDs: %d group(s)\n", len(groupIDs)))
			}
		}

		info.WriteString("\n")
	}

	return info.String(), warnings, errors
}

// checkEntityMFALinkage checks if the EOS entity is properly linked to MFA methods
func checkEntityMFALinkage(rc *eos_io.RuntimeContext, client *api.Client) (string, []string, []string) {
	var info strings.Builder
	var warnings []string
	var errors []string

	// Look up the EOS entity
	entityName := shared.EosID
	entityLookupPath := fmt.Sprintf(shared.EosEntityLookupPath, entityName)

	entityResp, err := client.Logical().Read(entityLookupPath)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to look up entity: %v", err))
		info.WriteString(fmt.Sprintf("  ✗ Cannot read entity: %v\n", err))
		return info.String(), warnings, errors
	}

	if entityResp == nil || entityResp.Data == nil {
		errors = append(errors, "EOS entity does not exist")
		info.WriteString("  ✗ Entity not found\n")
		info.WriteString("    Run 'eos create vault' to create the entity\n")
		return info.String(), warnings, errors
	}

	entityID, ok := entityResp.Data["id"].(string)
	if !ok || entityID == "" {
		errors = append(errors, "Entity ID is missing")
		info.WriteString("  ✗ Entity has no ID\n")
		return info.String(), warnings, errors
	}

	info.WriteString(fmt.Sprintf("  ✓ Entity found: %s\n", entityID))
	info.WriteString(fmt.Sprintf("    Name: %s\n", entityName))

	// Check if entity has MFA methods associated
	// The entity itself doesn't store MFA methods - they're associated via the method
	// But we can check if the entity has any MFA requirements

	// Check entity aliases (needed for auth)
	aliases, ok := entityResp.Data["aliases"].([]interface{})
	if !ok || len(aliases) == 0 {
		errors = append(errors, "Entity has no aliases - authentication will not work")
		info.WriteString("  ✗ No aliases configured\n")
	} else {
		info.WriteString(fmt.Sprintf("  ✓ Aliases: %d alias(es)\n", len(aliases)))

		// Find userpass alias
		hasUserpassAlias := false
		for _, aliasInterface := range aliases {
			alias, ok := aliasInterface.(map[string]interface{})
			if !ok {
				continue
			}

			mountAccessor := getStringValue(alias, "mount_accessor")
			aliasName := getStringValue(alias, "name")

			// Check against auth mounts to find which one is userpass
			authMounts, err := client.Sys().ListAuth()
			if err == nil {
				for path, mount := range authMounts {
					if mount.Accessor == mountAccessor && (mount.Type == "userpass" || strings.HasPrefix(path, "userpass")) {
						hasUserpassAlias = true
						info.WriteString(fmt.Sprintf("    • Userpass alias: %s (accessor: %s)\n", aliasName, mountAccessor))
						break
					}
				}
			}
		}

		if !hasUserpassAlias {
			warnings = append(warnings, "Entity has no userpass alias - userpass authentication may not work")
			info.WriteString("    ⚠ No userpass alias found\n")
		}
	}

	return info.String(), warnings, errors
}

// checkAuthAccessors retrieves all auth method accessors for validation
func checkAuthAccessors(client *api.Client) string {
	var info strings.Builder

	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		info.WriteString(fmt.Sprintf("  ✗ Cannot list auth mounts: %v\n", err))
		return info.String()
	}

	info.WriteString(fmt.Sprintf("  Found %d auth method(s):\n\n", len(authMounts)))

	for path, mount := range authMounts {
		info.WriteString(fmt.Sprintf("  • %s\n", path))
		info.WriteString(fmt.Sprintf("    Type: %s\n", mount.Type))
		info.WriteString(fmt.Sprintf("    Accessor: %s\n", mount.Accessor))
		info.WriteString(fmt.Sprintf("    Description: %s\n", mount.Description))
		info.WriteString("\n")
	}

	return info.String()
}
