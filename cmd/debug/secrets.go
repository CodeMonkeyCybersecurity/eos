// cmd/debug/secrets.go
// Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

package debug

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
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
		logger.Warn("⚠️  WARNING: Displaying plaintext secret values")
		logger.Warn("Ensure your terminal is secure and no screen sharing is active")
	}

	logger.Info("Running comprehensive secret diagnostics",
		zap.Strings("services", services),
		zap.Bool("show_plaintext", showPlaintext))

	// ASSESS - Discover environment and initialize secret manager
	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w\n"+
			"Fix: Ensure Vault or secret backend is properly configured", err)
	}

	secretManager, err := secrets.NewSecretManager(rc, envConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize secret manager: %w\n"+
			"Fix: Ensure Vault is accessible and properly configured", err)
	}

	// Get Vault client for metadata access (uses SDK, not shell commands)
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		logger.Warn("Failed to get Vault client, some metadata may be unavailable",
			zap.Error(err))
		vaultClient = nil
	}

	logger.Info("=== ENVIRONMENT INFORMATION ===")
	logger.Info(fmt.Sprintf("Environment: %s", envConfig.Environment))
	logger.Info(fmt.Sprintf("Vault Address: %s", envConfig.VaultAddr))
	logger.Info("")

	// INTERVENE - Process each service
	hasSecrets := false
	for _, service := range services {
		logger.Info(fmt.Sprintf("\n=== %s SECRETS DEBUG ===", strings.ToUpper(service)))

		// List secrets for this service using SDK methods
		secretNames, err := secretManager.ListSecrets(service)
		if err != nil {
			logger.Error("Failed to list secrets",
				zap.String("service", service),
				zap.Error(err))
			return fmt.Errorf("failed to list secrets for service '%s': %w\n"+
				"Fix: Ensure service exists in Vault and has proper permissions", service, err)
		}

		if len(secretNames) == 0 {
			logger.Info(fmt.Sprintf("No secrets found for service '%s'", service))
			logger.Info(fmt.Sprintf("Tip: Deploy the service with 'eos create %s' to generate secrets", service))
			continue
		}

		hasSecrets = true
		logger.Info(fmt.Sprintf("Total Secrets: %d", len(secretNames)))
		logger.Info("")

		// Debug each secret
		for idx, secretName := range secretNames {
			logger.Info(fmt.Sprintf("--- Secret %d/%d: %s ---", idx+1, len(secretNames), secretName))

			// Get secret path for metadata
			secretPath := fmt.Sprintf("services/%s/%s", envConfig.Environment, service)
			logger.Debug("Secret path", zap.String("path", secretPath))

			// Try to get metadata if Vault client is available
			if vaultClient != nil {
				displayVaultMetadata(rc, vaultClient, secretPath, secretName)
			}

			// Get secret value using SDK methods
			secretValue, err := secretManager.GetSecret(service, secretName)
			if err != nil {
				logger.Warn("Failed to read secret value",
					zap.String("service", service),
					zap.String("secret", secretName),
					zap.Error(err))
				logger.Info("VALUE: ERROR (failed to read)")
			} else {
				// Display value (redacted or plaintext based on --show flag)
				logger.Info("VALUE:")
				if !showPlaintext {
					logger.Info("  ***REDACTED*** (use --show to display)")
				} else {
					logger.Info(fmt.Sprintf("  %q", secretValue))
				}
			}

			// Try to get custom metadata using SDK
			if backend, ok := secretManager.GetBackend().(*secrets.VaultBackend); ok {
				customMetadata, err := backend.GetMetadata(secretPath)
				if err == nil && customMetadata != nil {
					logger.Info("CUSTOM METADATA:")
					if customMetadata.TTL != "" {
						logger.Info(fmt.Sprintf("  TTL: %s", customMetadata.TTL))
					}
					if customMetadata.CreatedBy != "" {
						logger.Info(fmt.Sprintf("  Created By: %s", customMetadata.CreatedBy))
					}
					if customMetadata.CreatedAt != "" {
						logger.Info(fmt.Sprintf("  Created At: %s", customMetadata.CreatedAt))
					}
					if customMetadata.Purpose != "" {
						logger.Info(fmt.Sprintf("  Purpose: %s", customMetadata.Purpose))
					}
					if customMetadata.Owner != "" {
						logger.Info(fmt.Sprintf("  Owner: %s", customMetadata.Owner))
					}
					if customMetadata.RotateAfter != "" {
						logger.Info(fmt.Sprintf("  Rotate After: %s", customMetadata.RotateAfter))
					}
					if len(customMetadata.Custom) > 0 {
						logger.Info("  Custom Fields:")
						for k, v := range customMetadata.Custom {
							logger.Info(fmt.Sprintf("    %s: %s", k, v))
						}
					}
				}
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
