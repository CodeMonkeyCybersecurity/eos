// pkg/debug/bionicgpt/vault_config_diagnostic.go
// Vault secret storage verification diagnostic
// Verifies that BionicGPT secrets are properly stored in HashiCorp Vault

package bionicgpt

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultConfigDiagnostic verifies BionicGPT secrets are stored in Vault
// Following P0 human-centric pattern: Provide proof of secret existence without exposing values
func VaultConfigDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault Secret Storage",
		Category:    "Configuration",
		Description: "Verify BionicGPT secrets are stored in HashiCorp Vault",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("═══════════════════════════════════════════════════════════════\n")
			output.WriteString("Vault Secret Storage Verification\n")
			output.WriteString("═══════════════════════════════════════════════════════════════\n\n")

			// Expected secrets for BionicGPT
			expectedSecrets := []string{
				"postgres_password",
				"jwt_secret",
				"litellm_master_key",
				"azure_api_key", // May be optional if using local embeddings
			}

			// Vault path for BionicGPT secrets
			vaultPath := "secret/services/production/bionicgpt"
			result.Metadata["vault_path"] = vaultPath

			output.WriteString(fmt.Sprintf("Vault Path: %s\n\n", vaultPath))

			// Check if Vault CLI is available
			vaultCmd := exec.CommandContext(ctx, "which", "vault")
			if err := vaultCmd.Run(); err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Vault CLI not found"
				output.WriteString("✗ Vault CLI not found in PATH\n")
				output.WriteString("Cannot verify secret storage without Vault CLI\n\n")
				output.WriteString("REMEDIATION:\n")
				output.WriteString("  Install Vault: sudo eos create vault\n")
				result.Output = output.String()
				result.Remediation = "Install Vault CLI: sudo eos create vault"
				logger.Warn("Vault CLI not found")
				return result, nil
			}

			output.WriteString("✓ Vault CLI found\n\n")

			// Check if Vault Agent token exists
			tokenPath := "/run/eos/vault_agent_eos.token"
			tokenCheckCmd := exec.CommandContext(ctx, "test", "-f", tokenPath)
			if err := tokenCheckCmd.Run(); err != nil {
				result.Status = debug.StatusError
				result.Message = "Vault Agent token not found"
				output.WriteString(fmt.Sprintf("✗ Vault Agent token not found: %s\n", tokenPath))
				output.WriteString("This token is used for Eos to authenticate to Vault\n\n")
				output.WriteString("REMEDIATION:\n")
				output.WriteString("  1. Check Vault Agent is running: systemctl status vault-agent-eos\n")
				output.WriteString("  2. Restart Vault Agent: systemctl restart vault-agent-eos\n")
				output.WriteString("  3. Verify Vault is healthy: eos debug vault\n")
				result.Output = output.String()
				result.Remediation = "Restart Vault Agent: systemctl restart vault-agent-eos"
				logger.Error("Vault Agent token not found", zap.String("token_path", tokenPath))
				return result, nil
			}

			output.WriteString(fmt.Sprintf("✓ Vault Agent token found: %s\n\n", tokenPath))

			// Check each expected secret
			foundSecrets := 0
			missingSecrets := []string{}

			output.WriteString("Secret Verification:\n")
			output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

			for _, secret := range expectedSecrets {
				secretPath := fmt.Sprintf("%s/%s", vaultPath, secret)

				// Use Vault CLI to check if secret exists (without printing value)
				// vault kv get -field=value prints the value, but -format=json shows metadata
				cmd := exec.CommandContext(ctx, "sh", "-c",
					fmt.Sprintf("VAULT_TOKEN=$(cat %s) vault kv get -format=json %s 2>&1", tokenPath, secretPath))
				checkOutput, err := cmd.CombinedOutput()

				if err != nil {
					// Secret doesn't exist or access denied
					outputStr := string(checkOutput)
					if strings.Contains(outputStr, "No value found") || strings.Contains(outputStr, "does not exist") {
						output.WriteString(fmt.Sprintf("  ✗ %s: NOT FOUND\n", secret))
						missingSecrets = append(missingSecrets, secret)
						logger.Warn("Secret not found in Vault",
							zap.String("secret", secret),
							zap.String("path", secretPath))
					} else if strings.Contains(outputStr, "permission denied") {
						output.WriteString(fmt.Sprintf("  ⚠ %s: ACCESS DENIED\n", secret))
						missingSecrets = append(missingSecrets, secret)
						logger.Warn("Permission denied accessing secret",
							zap.String("secret", secret),
							zap.String("path", secretPath))
					} else {
						output.WriteString(fmt.Sprintf("  ✗ %s: ERROR - %s\n", secret, strings.TrimSpace(outputStr)))
						missingSecrets = append(missingSecrets, secret)
						logger.Error("Error checking secret",
							zap.String("secret", secret),
							zap.String("error", outputStr))
					}
				} else {
					// Secret exists - show metadata without exposing value
					output.WriteString(fmt.Sprintf("  ✓ %s: EXISTS (value hidden for security)\n", secret))
					foundSecrets++
					logger.Info("Secret verified in Vault",
						zap.String("secret", secret))
				}
			}

			output.WriteString("\n")
			result.Metadata["found_secrets"] = foundSecrets
			result.Metadata["missing_secrets"] = len(missingSecrets)

			// Overall status
			if len(missingSecrets) == 0 {
				result.Status = debug.StatusOK
				result.Message = fmt.Sprintf("✓ All %d secrets verified in Vault", len(expectedSecrets))
				output.WriteString("═══════════════════════════════════════════════════════════════\n")
				output.WriteString(fmt.Sprintf("✓ SUCCESS: All %d secrets stored in Vault\n", len(expectedSecrets)))
				output.WriteString("═══════════════════════════════════════════════════════════════\n")
				logger.Info("All BionicGPT secrets verified in Vault")
			} else {
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("✗ Missing %d secrets in Vault", len(missingSecrets))
				output.WriteString("═══════════════════════════════════════════════════════════════\n")
				output.WriteString(fmt.Sprintf("✗ FAILED: %d secrets missing\n", len(missingSecrets)))
				output.WriteString("═══════════════════════════════════════════════════════════════\n\n")
				output.WriteString("Missing Secrets:\n")
				for _, secret := range missingSecrets {
					output.WriteString(fmt.Sprintf("  - %s\n", secret))
				}
				output.WriteString("\nREMEDIATION:\n")
				output.WriteString("  Option 1: Reinstall BionicGPT (will regenerate secrets)\n")
				output.WriteString("    sudo eos create bionicgpt --force\n\n")
				output.WriteString("  Option 2: Manually store secrets in Vault\n")
				output.WriteString("    VAULT_TOKEN=$(cat /run/eos/vault_agent_eos.token) vault kv put \\\n")
				output.WriteString(fmt.Sprintf("      %s/<secret_name> value=<secret_value>\n", vaultPath))
				result.Remediation = "Reinstall BionicGPT to regenerate secrets: sudo eos create bionicgpt --force"
				logger.Error("Missing secrets in Vault",
					zap.Strings("missing", missingSecrets))
			}

			// Additional security notes
			output.WriteString("\n")
			output.WriteString("Security Model:\n")
			output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			output.WriteString("• Secrets stored in Vault KV v2 engine\n")
			output.WriteString("• Access via Vault Agent (AppRole authentication)\n")
			output.WriteString("• Token stored in /run/eos/vault_agent_eos.token (root-only)\n")
			output.WriteString("• Automatic token rotation by Vault Agent\n")
			output.WriteString("• Secret values NEVER displayed in diagnostics\n")

			result.Output = output.String()
			return result, nil
		},
	}
}
