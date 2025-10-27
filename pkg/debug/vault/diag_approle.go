// pkg/debug/vault/diag_approle.go

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AppRoleDiagnostic provides comprehensive AppRole authentication diagnostics
// This checks the complete AppRole authentication chain:
// - AppRole auth method enabled
// - eos-approle role configuration (token_period, policies, TTLs)
// - Credential files (role_id, secret_id) existence and permissions
// - Token configuration validation (periodic tokens check)
//
// Use this diagnostic when troubleshooting:
// - Token expiration issues (check token_period vs token_max_ttl)
// - Authentication failures (check credentials and role config)
// - "Token is not renewable" warnings
// - Vault Agent authentication problems
func AppRoleDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "AppRole Authentication Configuration",
		Category:    "Authentication",
		Description: "Comprehensive AppRole auth method and role configuration analysis",
		Condition: func(ctx context.Context) bool {
			return true // Always run when --auth or --approle specified
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Debug("Starting AppRole diagnostic collection")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			output.WriteString("  APPROLE AUTHENTICATION DIAGNOSTICS\n")
			output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

			// Get Vault client (uses automatic authentication)
			rc := &eos_io.RuntimeContext{Ctx: ctx}
			client, clientErr := vault.GetVaultClient(rc)
			if clientErr != nil {
				result.Status = debug.StatusError
				result.Message = "Cannot connect to Vault"
				result.Remediation = "Ensure Vault is running: sudo systemctl status vault"
				output.WriteString(fmt.Sprintf("❌ Failed to create Vault client: %v\n", clientErr))
				result.Output = output.String()
				return result, nil
			}

			hasErrors := false
			hasWarnings := false

			// Section 1: AppRole Auth Method Status
			output.WriteString("1. AppRole Auth Method\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			authMethods, err := client.Sys().ListAuth()
			if err != nil {
				output.WriteString(fmt.Sprintf("❌ Failed to list auth methods: %v\n", err))
				hasErrors = true
			} else {
				appRoleEnabled := false
				for path, authMount := range authMethods {
					if authMount.Type == "approle" {
						appRoleEnabled = true
						output.WriteString(fmt.Sprintf("✓ AppRole enabled at: %s\n", path))
						output.WriteString(fmt.Sprintf("  Type: %s\n", authMount.Type))
						if authMount.Description != "" {
							output.WriteString(fmt.Sprintf("  Description: %s\n", authMount.Description))
						}
						result.Metadata["approle_path"] = path
						result.Metadata["approle_type"] = authMount.Type
					}
				}

				if !appRoleEnabled {
					output.WriteString("❌ AppRole auth method not enabled\n")
					output.WriteString("  Remediation: Enable AppRole during Vault setup\n")
					output.WriteString("    sudo eos create vault\n")
					hasErrors = true
				}
			}
			output.WriteString("\n")

			// Section 2: eos-approle Role Configuration (CRITICAL)
			output.WriteString("2. eos-approle Role Configuration\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			appRoleResp, err := client.Logical().Read("auth/approle/role/eos-approle")
			if err != nil {
				output.WriteString(fmt.Sprintf("❌ Failed to read eos-approle: %v\n", err))
				output.WriteString("  Remediation: Create AppRole during Vault setup\n")
				output.WriteString("    sudo eos create vault\n")
				hasErrors = true
			} else if appRoleResp == nil || appRoleResp.Data == nil {
				output.WriteString("❌ eos-approle role not found\n")
				output.WriteString("  Remediation: Create AppRole role\n")
				output.WriteString("    sudo eos create vault\n")
				hasErrors = true
			} else {
				// Parse AppRole configuration
				data := appRoleResp.Data
				result.Metadata["approle_config"] = data

				// Display key configuration parameters
				output.WriteString("Role: eos-approle\n\n")

				// Token Configuration (CRITICAL for periodic tokens)
				output.WriteString("Token Configuration:\n")

				// token_ttl
				if tokenTTL, ok := data["token_ttl"].(json.Number); ok {
					ttlInt, _ := tokenTTL.Int64()
					output.WriteString(fmt.Sprintf("  token_ttl:    %d seconds (%s)\n", ttlInt, formatDuration(ttlInt)))
					result.Metadata["token_ttl"] = ttlInt
				}

				// token_max_ttl (CRITICAL: Should be 0 or not set for periodic tokens)
				if tokenMaxTTL, ok := data["token_max_ttl"].(json.Number); ok {
					maxTTLInt, _ := tokenMaxTTL.Int64()
					output.WriteString(fmt.Sprintf("  token_max_ttl: %d seconds", maxTTLInt))

					if maxTTLInt > 0 {
						output.WriteString(" ⚠️  WARNING: May conflict with token_period!\n")
						hasWarnings = true
					} else {
						output.WriteString(" ✓ (not set - correct for periodic tokens)\n")
					}
					result.Metadata["token_max_ttl"] = maxTTLInt
				} else {
					output.WriteString("  token_max_ttl: not set ✓ (correct for periodic tokens)\n")
					result.Metadata["token_max_ttl"] = 0
				}

				// token_period (CRITICAL: MUST be set for infinite renewal)
				if tokenPeriod, ok := data["token_period"].(json.Number); ok {
					periodInt, _ := tokenPeriod.Int64()
					if periodInt > 0 {
						output.WriteString(fmt.Sprintf("  token_period:  %d seconds (%s) ✓ Periodic token enabled\n", periodInt, formatDuration(periodInt)))
					} else {
						output.WriteString("  token_period:  0 ❌ Tokens will expire at max_ttl!\n")
						hasErrors = true
					}
					result.Metadata["token_period"] = periodInt
				} else {
					output.WriteString("  token_period:  not set ❌ Tokens will expire at max_ttl!\n")
					output.WriteString("    Remediation: Update AppRole to use periodic tokens\n")
					output.WriteString("      vault write auth/approle/role/eos-approle token_period=4h\n")
					hasErrors = true
					result.Metadata["token_period"] = 0
				}

				output.WriteString("\n")

				// SecretID Configuration
				output.WriteString("SecretID Configuration:\n")
				if secretIDTTL, ok := data["secret_id_ttl"].(json.Number); ok {
					ttlInt, _ := secretIDTTL.Int64()
					output.WriteString(fmt.Sprintf("  secret_id_ttl: %d seconds (%s)\n", ttlInt, formatDuration(ttlInt)))
					result.Metadata["secret_id_ttl"] = ttlInt
				}

				if secretIDNumUses, ok := data["secret_id_num_uses"].(json.Number); ok {
					numUses, _ := secretIDNumUses.Int64()
					if numUses == 0 {
						output.WriteString("  secret_id_num_uses: unlimited\n")
					} else {
						output.WriteString(fmt.Sprintf("  secret_id_num_uses: %d\n", numUses))
					}
				}

				output.WriteString("\n")

				// Policies
				output.WriteString("Policies:\n")
				if policies, ok := data["policies"].([]interface{}); ok {
					if len(policies) == 0 {
						output.WriteString("  ⚠️  No policies attached!\n")
						hasWarnings = true
					} else {
						for _, policy := range policies {
							output.WriteString(fmt.Sprintf("  - %v\n", policy))
						}
					}
					result.Metadata["policies"] = policies
				} else if tokenPolicies, ok := data["token_policies"].([]interface{}); ok {
					for _, policy := range tokenPolicies {
						output.WriteString(fmt.Sprintf("  - %v\n", policy))
					}
					result.Metadata["policies"] = tokenPolicies
				}

				output.WriteString("\n")

				// Binding Configuration
				output.WriteString("Binding Configuration:\n")
				if bindSecretID, ok := data["bind_secret_id"].(bool); ok {
					if bindSecretID {
						output.WriteString("  bind_secret_id: true ✓ (SecretID required for auth)\n")
					} else {
						output.WriteString("  bind_secret_id: false ⚠️  (Any RoleID can auth!)\n")
						hasWarnings = true
					}
				}
			}
			output.WriteString("\n")

			// Section 3: Credential Files
			output.WriteString("3. AppRole Credential Files\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			roleIDPath := shared.AppRolePaths.RoleID
			secretIDPath := shared.AppRolePaths.SecretID

			// Check role_id file
			roleIDStat, roleIDErr := os.Stat(roleIDPath)
			if roleIDErr == nil {
				output.WriteString(fmt.Sprintf("✓ RoleID file: %s\n", roleIDPath))
				output.WriteString(fmt.Sprintf("  Size: %d bytes\n", roleIDStat.Size()))
				output.WriteString(fmt.Sprintf("  Permissions: %s\n", roleIDStat.Mode().Perm()))

				if roleIDStat.Mode().Perm() != 0600 {
					output.WriteString("  ⚠️  Permissions should be 0600\n")
					hasWarnings = true
				}
			} else {
				output.WriteString(fmt.Sprintf("❌ RoleID file missing: %s\n", roleIDPath))
				output.WriteString("  Error: " + roleIDErr.Error() + "\n")
				hasErrors = true
			}

			output.WriteString("\n")

			// Check secret_id file
			secretIDStat, secretIDErr := os.Stat(secretIDPath)
			if secretIDErr == nil {
				output.WriteString(fmt.Sprintf("✓ SecretID file: %s\n", secretIDPath))
				output.WriteString(fmt.Sprintf("  Size: %d bytes\n", secretIDStat.Size()))
				output.WriteString(fmt.Sprintf("  Permissions: %s\n", secretIDStat.Mode().Perm()))

				if secretIDStat.Mode().Perm() != 0600 {
					output.WriteString("  ⚠️  Permissions should be 0600\n")
					hasWarnings = true
				}
			} else {
				output.WriteString(fmt.Sprintf("❌ SecretID file missing: %s\n", secretIDPath))
				output.WriteString("  Error: " + secretIDErr.Error() + "\n")
				hasErrors = true
			}

			output.WriteString("\n")

			// Section 4: Analysis and Recommendations
			output.WriteString("4. Analysis\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			if !hasErrors && !hasWarnings {
				output.WriteString("✓ AppRole configuration is correct\n")
				output.WriteString("✓ Periodic tokens enabled - tokens will renew infinitely\n")
				output.WriteString("✓ Credential files exist with correct permissions\n")
				result.Status = debug.StatusOK
				result.Message = "AppRole authentication is correctly configured"
			} else if hasErrors {
				output.WriteString("Issues detected:\n\n")

				if appRoleResp != nil && appRoleResp.Data != nil {
					data := appRoleResp.Data

					// Check for missing token_period
					tokenPeriod, hasPeriod := data["token_period"].(json.Number)
					periodInt := int64(0)
					if hasPeriod {
						periodInt, _ = tokenPeriod.Int64()
					}

					tokenMaxTTL, hasMaxTTL := data["token_max_ttl"].(json.Number)
					maxTTLInt := int64(0)
					if hasMaxTTL {
						maxTTLInt, _ = tokenMaxTTL.Int64()
					}

					if !hasPeriod || periodInt == 0 {
						output.WriteString("❌ CRITICAL: token_period not set\n")
						output.WriteString("   Impact: Tokens will expire and cannot be renewed infinitely\n")
						output.WriteString("   This causes deployment failures when tokens expire\n\n")
						output.WriteString("   Fix: Update AppRole configuration\n")
						output.WriteString("     vault write auth/approle/role/eos-approle \\\n")
						output.WriteString("       token_ttl=4h \\\n")
						output.WriteString("       token_period=4h \\\n")
						output.WriteString("       secret_id_ttl=24h\n\n")
					} else if hasMaxTTL && maxTTLInt > 0 {
						output.WriteString("⚠️  WARNING: Both token_period and token_max_ttl are set\n")
						output.WriteString("   Impact: Tokens may still expire at max_ttl despite being periodic\n")
						output.WriteString("   HashiCorp docs: \"When a period and an explicit max TTL were both set,\n")
						output.WriteString("   once the explicit max TTL is reached, the token will be revoked.\"\n\n")
						output.WriteString("   Fix: Remove token_max_ttl for true periodic tokens\n")
						output.WriteString("     vault write auth/approle/role/eos-approle \\\n")
						output.WriteString("       token_ttl=4h \\\n")
						output.WriteString("       token_period=4h \\\n")
						output.WriteString("       secret_id_ttl=24h\n\n")
					}
				}

				if roleIDErr != nil || secretIDErr != nil {
					output.WriteString("❌ Credential files missing\n")
					output.WriteString("   Remediation: Recreate AppRole credentials\n")
					output.WriteString("     sudo eos create vault\n\n")
				}

				result.Status = debug.StatusError
				result.Message = "AppRole configuration has errors"
				result.Remediation = "Follow remediation steps in Analysis section"
			} else if hasWarnings {
				output.WriteString("⚠️  Configuration warnings detected\n")
				output.WriteString("   Review warnings above and consider addressing them\n\n")

				result.Status = debug.StatusWarning
				result.Message = "AppRole configuration has warnings"
			}

			output.WriteString("\n")
			output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

			result.Output = output.String()

			logger.Info("AppRole diagnostic collection complete",
				zap.Bool("has_errors", hasErrors),
				zap.Bool("has_warnings", hasWarnings),
				zap.String("status", string(result.Status)))

			return result, nil
		},
	}
}

// formatDuration converts seconds to human-readable duration
func formatDuration(seconds int64) string {
	if seconds == 0 {
		return "0s"
	}

	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60

	var parts []string
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if secs > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", secs))
	}

	return strings.Join(parts, " ")
}
