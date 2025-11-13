// cmd/debug/secrets.go
// Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

package debug

import (
	"fmt"
	"os"
	"strings"
	"time"

	consulenv "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	sharedvault "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Available services for secret management
var availableServicesForDebug = []string{
	"consul",
	"authentik",
	"bionicgpt",
	"wazuh",
}

var debugSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Debug secrets with comprehensive diagnostics",
	Long: `Debug secrets provides comprehensive diagnostic information for secrets.

This command displays:
- Service and environment information
- Secret names and metadata
- Version history (current version, total versions)
- Creation and modification timestamps
- Secret values (redacted by default, --show for plaintext)
- Backend information (Vault vs file)

By default, secret values are REDACTED for security. Use the --show flag
to display plaintext values.

EXAMPLES:
  # Debug Consul secrets (redacted values)
  eos debug secrets --consul

  # Debug Authentik secrets with plaintext values
  eos debug secrets --authentik --show

  # Debug all secrets across all services
  eos debug secrets --all

SECURITY:
  Secret values are redacted by default. Use --show flag to display plaintext.

Output is automatically saved to ~/.eos/debug/eos-debug-secrets-{timestamp}.txt`,

	RunE: eos_cli.Wrap(runDebugSecrets),
}

func init() {
	addServiceFlagsToDebug(debugSecretsCmd)
	debugSecretsCmd.Flags().Bool("show", false, "Display plaintext secret values (default: redacted)")
	debugCmd.AddCommand(debugSecretsCmd)
}

// addServiceFlagsToDebug adds mutually exclusive service selector flags
func addServiceFlagsToDebug(cmd *cobra.Command) {
	cmd.Flags().Bool("consul", false, "Debug Consul secrets")
	cmd.Flags().Bool("authentik", false, "Debug Authentik secrets")
	cmd.Flags().Bool("bionicgpt", false, "Debug BionicGPT secrets")
	cmd.Flags().Bool("wazuh", false, "Debug Wazuh secrets")
	cmd.Flags().Bool("all", false, "Debug secrets for all services")
	cmd.Flags().String("environment", "", "Override environment (requires CONSUL_EMERGENCY_OVERRIDE=true)")
	cmd.MarkFlagsMutuallyExclusive("consul", "authentik", "bionicgpt", "wazuh", "all")
}

// getSelectedServicesForDebug returns list of services to target based on flags
func getSelectedServicesForDebug(cmd *cobra.Command) ([]string, error) {
	var selected []string

	// Check each service flag
	for _, svc := range availableServicesForDebug {
		if flagVal, _ := cmd.Flags().GetBool(svc); flagVal {
			selected = append(selected, svc)
		}
	}

	// Check --all flag
	allFlag, _ := cmd.Flags().GetBool("all")

	// Validation logic
	if allFlag {
		if len(selected) > 0 {
			return nil, fmt.Errorf("cannot use --all with specific service flags")
		}
		return availableServicesForDebug, nil
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("must specify a service (--consul, --authentik, --bionicgpt, --wazuh) or --all\n" +
			"Example: eos debug secrets --consul")
	}

	if len(selected) > 1 {
		return nil, fmt.Errorf("cannot specify multiple service flags (use --all for all services)")
	}

	return selected, nil
}

// resolveEnvironment resolves the environment using correct precedence: Consul authoritative, flag for emergency override.
// Implements fail-closed security: blocks operations when environment cannot be determined.
func resolveEnvironmentDebug(rc *eos_io.RuntimeContext, flagEnv string) (sharedvault.Environment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// 1. Check emergency override
	if os.Getenv("CONSUL_EMERGENCY_OVERRIDE") == "true" {
		if flagEnv == "" {
			return "", fmt.Errorf("CONSUL_EMERGENCY_OVERRIDE requires --environment flag\n\n" +
				"Emergency override allows bypassing Consul when it's unavailable.\n" +
				"You MUST specify --environment flag to use emergency override.\n\n" +
				"Example:\n" +
				"  CONSUL_EMERGENCY_OVERRIDE=true eos debug secrets --consul --environment development --show")
		}

		// Validate emergency override environment
		if err := sharedvault.ValidateEnvironment(flagEnv); err != nil {
			return "", fmt.Errorf("invalid --environment flag: %w", err)
		}

		logger.Warn("Using emergency override - Consul bypassed",
			zap.String("environment", flagEnv),
			zap.String("reason", "CONSUL_EMERGENCY_OVERRIDE=true"),
			zap.String("audit", "emergency_override"))

		return sharedvault.Environment(flagEnv), nil
	}

	// 2. Query Consul (authoritative)
	consulEnv, err := consulenv.DiscoverFromConsul(rc)
	if err != nil {
		// FAIL-CLOSED: No fallback to development
		return "", fmt.Errorf("cannot determine environment from Consul: %w\n\n"+
			"Consul is the authoritative source for environment configuration.\n"+
			"This system fails-closed for security (no fallback to development).\n\n"+
			"Remediation:\n"+
			"1. Ensure Consul is running: systemctl status consul\n"+
			"2. Set environment: eos update consul --environment <env>\n"+
			"3. Emergency override (Consul unavailable): CONSUL_EMERGENCY_OVERRIDE=true eos debug secrets --consul --environment <env> --show",
			err)
	}

	// 3. Verify flag matches Consul (if provided)
	if flagEnv != "" && flagEnv != string(consulEnv) {
		return "", fmt.Errorf("--environment flag (%s) does not match Consul environment (%s)\n\n"+
			"Consul is authoritative. The --environment flag is rejected when it conflicts.\n"+
			"This prevents accidental exposure of wrong environment secrets.\n\n"+
			"Choose ONE of:\n"+
			"1. Remove --environment flag to use Consul value: %s\n"+
			"2. Update Consul: eos update consul --environment %s\n"+
			"3. Emergency override (bypass Consul): CONSUL_EMERGENCY_OVERRIDE=true eos debug secrets --consul --environment %s --show",
			flagEnv, consulEnv, consulEnv, flagEnv, flagEnv)
	}

	logger.Info("Using environment from Consul",
		zap.String("environment", string(consulEnv)),
		zap.String("source", "consul"),
		zap.String("audit", "environment_resolution"))

	return consulEnv, nil
}

// runDebugSecrets orchestrates comprehensive secret diagnostics.
// Follows Assess → Intervene → Evaluate pattern.
func runDebugSecrets(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get selected services
	services, err := getSelectedServicesForDebug(cmd)
	if err != nil {
		logger.Error("Invalid service selection", zap.Error(err))
		return err
	}

	// Get --show flag
	showPlaintext, _ := cmd.Flags().GetBool("show")

	if showPlaintext {
		logger.Warn("  WARNING: Displaying plaintext secret values")
		logger.Warn("Ensure your terminal is secure and no screen sharing is active")
	}

	logger.Info("Running comprehensive secret diagnostics",
		zap.Strings("services", services),
		zap.Bool("show_plaintext", showPlaintext))

	// ASSESS - Resolve environment (Consul authoritative, fail-closed)
	flagEnv, _ := cmd.Flags().GetString("environment")
	env, err := resolveEnvironmentDebug(rc, flagEnv)
	if err != nil {
		return err
	}

	logger.Info("Resolved environment",
		zap.String("environment", string(env)))

	// Get Vault client for metadata access (uses SDK, not shell commands)
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get Vault client: %w\n\n"+
			"Remediation:\n"+
			"  - Ensure Vault is running: systemctl status vault\n"+
			"  - Check Vault status: vault status\n"+
			"  - Ensure Vault agent is running: systemctl status vault-agent-eos", err)
	}

	secretMgr := vault.NewVaultSecretManager(rc, vaultClient)

	logger.Info("=== ENVIRONMENT INFORMATION ===")
	logger.Info(fmt.Sprintf("Environment: %s", env))
	logger.Info(fmt.Sprintf("Environment Source: Consul KV"))
	logger.Info("")

	// INTERVENE - Process each service
	hasSecrets := false
	for _, serviceName := range services {
		logger.Info(fmt.Sprintf("\n=== %s SECRETS DEBUG (%s) ===", strings.ToUpper(serviceName), strings.ToUpper(string(env))))

		// Convert service name to Service type
		service := sharedvault.Service(serviceName)
		if err := sharedvault.ValidateService(serviceName); err != nil {
			logger.Warn("Skipping invalid service", zap.String("service", serviceName), zap.Error(err))
			continue
		}

		// Get service metadata
		metadata, err := secretMgr.GetServiceMetadata(rc.Ctx, env, service)
		if err != nil {
			logger.Warn("Failed to get metadata for service",
				zap.String("service", serviceName),
				zap.String("environment", string(env)),
				zap.Error(err))
			continue
		}

		if len(metadata.Keys) == 0 {
			logger.Info(fmt.Sprintf("No secrets found for service '%s' in environment '%s'", serviceName, env))
			logger.Info(fmt.Sprintf("Tip: Deploy the service with 'eos create %s' to generate secrets", serviceName))
			continue
		}

		hasSecrets = true
		logger.Info(fmt.Sprintf("Total Secrets: %d", len(metadata.Keys)))
		logger.Info(fmt.Sprintf("Current Version: %d", metadata.CurrentVersion))
		logger.Info(fmt.Sprintf("Created: %s", metadata.CreatedTime.Format(time.RFC3339)))
		logger.Info(fmt.Sprintf("Updated: %s", metadata.UpdatedTime.Format(time.RFC3339)))
		logger.Info(fmt.Sprintf("Path: %s", metadata.Path))
		logger.Info("")

		// Get service secrets
		secretsData, err := secretMgr.GetServiceSecrets(rc.Ctx, env, service)
		if err != nil {
			logger.Warn("Failed to get secrets for service",
				zap.String("service", serviceName),
				zap.Error(err))
			continue
		}

		// Debug each secret
		idx := 0
		for secretName, secretValue := range secretsData {
			idx++
			logger.Info(fmt.Sprintf("--- Secret %d/%d: %s ---", idx, len(secretsData), secretName))

			// Display value (redacted or plaintext based on --show flag)
			logger.Info("VALUE:")
			if !showPlaintext {
				logger.Info("  ***REDACTED*** (use --show to display)")
			} else {
				// Convert to string
				valueStr, ok := secretValue.(string)
				if !ok {
					valueStr = fmt.Sprintf("%v", secretValue)
				}
				logger.Info(fmt.Sprintf("  %q", valueStr))
			}

			logger.Info("")
		}

		// Display custom metadata if available
		if len(metadata.CustomMetadata) > 0 {
			logger.Info("CUSTOM METADATA:")
			for key, value := range metadata.CustomMetadata {
				logger.Info(fmt.Sprintf("  %s: %s", key, value))
			}
			logger.Info("")
		}

		// Display version history
		if len(metadata.Versions) > 0 {
			logger.Info("VERSION HISTORY:")
			for versionNum, versionInfo := range metadata.Versions {
				status := "active"
				if versionInfo.Destroyed {
					status = "destroyed"
				} else if versionInfo.DeletedTime != nil {
					status = "deleted"
				}
				logger.Info(fmt.Sprintf("  Version %d: %s (created: %s)",
					versionNum, status, versionInfo.CreatedTime.Format(time.RFC3339)))
			}
			logger.Info("")
		}
	}

	// EVALUATE - Final summary
	if !hasSecrets {
		logger.Info("\n=== SUMMARY ===")
		logger.Info("No secrets found for any of the specified services")
		logger.Info("Tip: Use 'eos create <service>' to deploy services and generate secrets")
	} else {
		logger.Info("\n=== DIAGNOSTICS COMPLETE ===")
		logger.Info("Secret diagnostics completed successfully")
		if !showPlaintext {
			logger.Info("Tip: Use --show flag to display plaintext values")
		}
	}

	return nil
}

// displayVaultMetadata retrieves and displays Vault KV v2 metadata using SDK methods
func displayVaultMetadata(rc *eos_io.RuntimeContext, client *vaultapi.Client, basePath, secretName string) {
	logger := otelzap.Ctx(rc.Ctx)

	// Construct metadata path for Vault KV v2
	// The path is: secret/metadata/services/{env}/{service}
	metadataPath := fmt.Sprintf("secret/metadata/%s", basePath)

	logger.Debug("Reading Vault metadata",
		zap.String("path", metadataPath))

	// Use Vault SDK to read metadata (not shell commands)
	resp, err := client.Logical().ReadWithContext(rc.Ctx, metadataPath)
	if err != nil {
		logger.Debug("Failed to read Vault metadata",
			zap.Error(err),
			zap.String("path", metadataPath))
		return
	}

	if resp == nil || resp.Data == nil {
		logger.Debug("No metadata found at path", zap.String("path", metadataPath))
		return
	}

	// Extract metadata information
	logger.Info("VAULT METADATA:")
	logger.Info(fmt.Sprintf("  Path: %s", metadataPath))

	if createdTime, ok := resp.Data["created_time"].(string); ok {
		logger.Info(fmt.Sprintf("  Created: %s", createdTime))
	}

	if currentVersion, ok := resp.Data["current_version"].(float64); ok {
		logger.Info(fmt.Sprintf("  Current Version: %.0f", currentVersion))
	}

	if versions, ok := resp.Data["versions"].(map[string]interface{}); ok {
		logger.Info(fmt.Sprintf("  Total Versions: %d", len(versions)))

		// Display version history
		if len(versions) > 0 {
			logger.Info("  Version History:")
			for vNum, vData := range versions {
				if vInfo, ok := vData.(map[string]interface{}); ok {
					status := "active"
					if destroyed, ok := vInfo["destroyed"].(bool); ok && destroyed {
						status = "destroyed"
					} else if deletionTime, ok := vInfo["deletion_time"].(string); ok && deletionTime != "" {
						status = "deleted"
					}

					createdTime := "unknown"
					if ct, ok := vInfo["created_time"].(string); ok {
						// Parse and format timestamp for readability
						if parsedTime, err := time.Parse(time.RFC3339, ct); err == nil {
							createdTime = parsedTime.Format("2006-01-02 15:04:05")
						} else {
							createdTime = ct
						}
					}

					logger.Info(fmt.Sprintf("    - v%s: created %s (%s)", vNum, createdTime, status))
				}
			}
		}
	}
}
