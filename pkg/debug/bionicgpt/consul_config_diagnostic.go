// pkg/debug/bionicgpt/consul_config_diagnostic.go
// Consul KV configuration cache verification diagnostic
// Verifies that BionicGPT configuration is properly cached in HashiCorp Consul

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

// ConsulConfigDiagnostic verifies BionicGPT configuration is cached in Consul KV
// Following P0 human-centric pattern: Show configuration state clearly for debugging
// P1 FIX: Now context-aware - checks Consul reachability pre-install, config keys post-install
func ConsulConfigDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Consul Configuration Cache",
		Category:    "Configuration",
		Description: "Verify BionicGPT configuration is cached in HashiCorp Consul KV",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("═══════════════════════════════════════════════════════════════\n")
			output.WriteString("Consul Configuration Cache Verification\n")
			output.WriteString("═══════════════════════════════════════════════════════════════\n\n")

			// Expected configuration keys in Consul KV
			expectedKeys := map[string]string{
				"azure_endpoint":              "Azure OpenAI endpoint URL",
				"azure_chat_deployment":       "Azure chat model deployment name",
				"azure_embeddings_deployment": "Azure embeddings deployment name",
				"port":                        "BionicGPT web interface port",
				"litellm_port":                "LiteLLM proxy internal port",
			}

			// Consul KV path for BionicGPT config
			consulPath := "service/bionicgpt/config/azure_openai"
			result.Metadata["consul_path"] = consulPath

			output.WriteString(fmt.Sprintf("Consul KV Path: %s\n\n", consulPath))

			// Check if Consul CLI is available
			consulCmd := exec.CommandContext(ctx, "which", "consul")
			if err := consulCmd.Run(); err != nil {
				result.Status = debug.StatusSkipped
				result.Message = "Consul CLI not found (Consul not required for Docker Compose deployment)"
				output.WriteString("ℹ Consul CLI not found in PATH\n")
				output.WriteString("Consul is optional for Docker Compose deployments.\n")
				output.WriteString("Consul is required only for Nomad deployments.\n\n")
				output.WriteString("NOTE:\n")
				output.WriteString("  If you want to use Consul for service discovery:\n")
				output.WriteString("    sudo eos create consul\n")
				result.Output = output.String()
				result.Remediation = "Consul is optional - install with: sudo eos create consul"
				logger.Info("Consul CLI not found (optional for Docker Compose)")
				return result, nil
			}

			output.WriteString("✓ Consul CLI found\n\n")

			// Check if Consul is reachable
			healthCmd := exec.CommandContext(ctx, "consul", "info")
			if err := healthCmd.Run(); err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Consul is installed but not reachable (optional for Docker Compose)"
				output.WriteString("⚠ Consul is installed but not reachable\n")
				output.WriteString("Consul is optional for Docker Compose deployments.\n\n")
				output.WriteString("If you want to use Consul:\n")
				output.WriteString("  1. Check Consul is running: systemctl status consul\n")
				output.WriteString("  2. Start Consul: systemctl start consul\n")
				output.WriteString("  3. Verify Consul health: eos debug consul\n")
				result.Output = output.String()
				result.Remediation = "Consul is optional - start with: systemctl start consul"
				logger.Info("Consul is installed but not reachable (optional)")
				return result, nil
			}

			output.WriteString("✓ Consul is reachable\n\n")

			// Check each expected configuration key
			foundKeys := 0
			missingKeys := []string{}

			output.WriteString("Configuration Key Verification:\n")
			output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

			for key, description := range expectedKeys {
				keyPath := fmt.Sprintf("%s/%s", consulPath, key)

				// Use Consul CLI to get key value
				cmd := exec.CommandContext(ctx, "consul", "kv", "get", keyPath)
				keyOutput, err := cmd.CombinedOutput()

				if err != nil {
					// Key doesn't exist
					output.WriteString(fmt.Sprintf("  ✗ %s: NOT FOUND\n", key))
					output.WriteString(fmt.Sprintf("     Description: %s\n", description))
					missingKeys = append(missingKeys, key)
					logger.Warn("Configuration key not found in Consul",
						zap.String("key", key),
						zap.String("path", keyPath))
				} else {
					// Key exists - show value (non-secret config)
					value := strings.TrimSpace(string(keyOutput))
					output.WriteString(fmt.Sprintf("  ✓ %s: %s\n", key, value))
					output.WriteString(fmt.Sprintf("     Description: %s\n", description))
					foundKeys++
					logger.Info("Configuration key verified in Consul",
						zap.String("key", key),
						zap.String("value", value))
				}
			}

			output.WriteString("\n")
			result.Metadata["found_keys"] = foundKeys
			result.Metadata["missing_keys"] = len(missingKeys)

			// Overall status (P1 FIX: Context-aware status messages)
			if len(missingKeys) == 0 {
				result.Status = debug.StatusOK
				result.Message = fmt.Sprintf("✓ All %d configuration keys verified in Consul", len(expectedKeys))
				output.WriteString("═══════════════════════════════════════════════════════════════\n")
				output.WriteString(fmt.Sprintf("✓ SUCCESS: All %d configuration keys cached\n", len(expectedKeys)))
				output.WriteString("═══════════════════════════════════════════════════════════════\n")
				logger.Info("All BionicGPT configuration keys verified in Consul")
			} else {
				// P1 FIX: Check if this is a fresh install (no keys at all)
				// Fresh install is NORMAL - not a warning
				if foundKeys == 0 {
					result.Status = debug.StatusSkipped
					result.Message = "No configuration keys found (expected for Docker Compose deployment)"
					output.WriteString("═══════════════════════════════════════════════════════════════\n")
					output.WriteString("ℹ INFO: No configuration keys found in Consul\n")
					output.WriteString("═══════════════════════════════════════════════════════════════\n\n")
					output.WriteString("This is NORMAL for Docker Compose deployments.\n")
					output.WriteString("Consul configuration cache is optional.\n\n")
					output.WriteString("Configuration is stored in:\n")
					output.WriteString("  • /opt/bionicgpt/.env (environment variables)\n")
					output.WriteString("  • HashiCorp Vault (secrets)\n\n")
					output.WriteString("Consul is only required for:\n")
					output.WriteString("  • Nomad enterprise deployments\n")
					output.WriteString("  • Multi-node service discovery\n")
					output.WriteString("  • Dynamic configuration updates\n")
					result.Remediation = "No action needed - Consul is optional for Docker Compose deployments"
					logger.Info("No configuration keys found in Consul (normal for Docker Compose)")
				} else {
					// P1 FIX: Partial configuration found - this IS concerning
					result.Status = debug.StatusWarning
					result.Message = fmt.Sprintf("⚠ Partial configuration: %d/%d keys found", foundKeys, len(expectedKeys))
					output.WriteString("═══════════════════════════════════════════════════════════════\n")
					output.WriteString(fmt.Sprintf("⚠ WARNING: Partial configuration (%d/%d keys)\n", foundKeys, len(expectedKeys)))
					output.WriteString("═══════════════════════════════════════════════════════════════\n\n")
					output.WriteString("Missing Keys:\n")
					for _, key := range missingKeys {
						output.WriteString(fmt.Sprintf("  - %s: %s\n", key, expectedKeys[key]))
					}
					output.WriteString("\nREMEDIATION:\n")
					output.WriteString("  Option 1: Reinstall BionicGPT (will repopulate configuration)\n")
					output.WriteString("    sudo eos create bionicgpt --deployment=nomad --force\n\n")
					output.WriteString("  Option 2: Manually add missing keys to Consul KV\n")
					output.WriteString("    consul kv put service/bionicgpt/config/azure_openai/<key> <value>\n")
					result.Remediation = "Reinstall with: sudo eos create bionicgpt --deployment=nomad --force"
					logger.Warn("Partial configuration in Consul - some keys missing",
						zap.Strings("missing", missingKeys),
						zap.Int("found", foundKeys),
						zap.Int("expected", len(expectedKeys)))
				}
			}

			// Additional notes about Consul KV usage
			output.WriteString("\n")
			output.WriteString("Configuration Model:\n")
			output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			output.WriteString("• Non-secret config cached in Consul KV for easy updates\n")
			output.WriteString("• Service discovery data stored in Consul Catalog\n")
			output.WriteString("• Dynamic updates without redeployment\n")
			output.WriteString("• Consul Template can watch for changes and reload services\n")
			output.WriteString("• Secrets (passwords, keys) stored in Vault, not Consul\n\n")
			output.WriteString("Update Configuration:\n")
			output.WriteString("  consul kv put service/bionicgpt/config/azure_openai/<key> <new_value>\n")
			output.WriteString("  # Then restart BionicGPT to pick up changes:\n")
			output.WriteString("  docker compose -f /opt/bionicgpt/docker-compose.yml restart\n")

			result.Output = output.String()
			return result, nil
		},
	}
}
