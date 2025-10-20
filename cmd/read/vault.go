// cmd/read/vault.go
package read

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func init() {
	// Add subcommands to vault command (these stay as subcommands)
	InspectVaultCmd.AddCommand(InspectVaultAgentCmd)
	InspectVaultCmd.AddCommand(InspectVaultLDAPCmd)

	// Register main vault command
	ReadCmd.AddCommand(InspectVaultCmd)

	// NOTE: InspectVaultInitCmd is NO LONGER registered at top level
	// It is now accessed via: eos read vault --init
	// Top-level registration removed as part of command refactoring

	// Add flags for command variants
	InspectVaultCmd.Flags().Bool("init", false, "Securely inspect Vault initialization data")
	InspectVaultCmd.Flags().Bool("status", false, "Show comprehensive Vault status and integration")

	// Flags for --init variant (forwarded to InspectVaultInitCmd)
	InspectVaultCmd.Flags().Bool("no-redact", false, "Show sensitive data in plaintext (requires confirmation)")
	InspectVaultCmd.Flags().String("export", "console", "Export format: console, json, secure")
	InspectVaultCmd.Flags().Bool("status-only", false, "Show only Vault status information (no sensitive data)")
	InspectVaultCmd.Flags().String("output", "", "Output file path for export formats")
	InspectVaultCmd.Flags().String("reason", "", "Access reason for audit logging")
	InspectVaultCmd.Flags().Bool("no-confirm", false, "Skip confirmation prompts (use with caution)")

	// Keep existing flags for InspectVaultInitCmd (for backward compat if called directly)
	InspectVaultInitCmd.Flags().Bool("no-redact", false, "Show sensitive data in plaintext (requires confirmation)")
	InspectVaultInitCmd.Flags().String("export", "console", "Export format: console, json, secure")
	InspectVaultInitCmd.Flags().Bool("status-only", false, "Show only Vault status information (no sensitive data)")
	InspectVaultInitCmd.Flags().String("output", "", "Output file path for export formats")
	InspectVaultInitCmd.Flags().String("reason", "", "Access reason for audit logging")
	InspectVaultInitCmd.Flags().Bool("no-confirm", false, "Skip confirmation prompts (use with caution)")

	// Flags for vault agent subcommand
	InspectVaultAgentCmd.Flags().Bool("json", false, "Output status in JSON format for automation")
}

// InspectVaultInitCmd displays Vault initialization keys, root token, and eos user credentials with enhanced security.
var InspectVaultInitCmd = &cobra.Command{
	Use:   "vault-init",
	Short: "Securely inspect Vault initialization data with comprehensive status",
	Long: `Securely reads and displays Vault initialization data including root token, unseal keys, 
and eos credentials with comprehensive status information, integrity verification, and audit logging.

Security Features:
  • Access control and user verification
  • Optional sensitive data redaction
  • Comprehensive audit logging
  • File integrity verification
  • Current Vault status integration

Examples:
  sudo eos read vault-init                    # Secure read with redaction
  sudo eos read vault-init --no-redact        # Show plaintext (requires confirmation)
  sudo eos read vault-init --export json      # Export to JSON format
  sudo eos read vault-init --status-only      # Show only status information`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		// Parse command flags
		noRedact, _ := cmd.Flags().GetBool("no-redact")
		exportFormat, _ := cmd.Flags().GetString("export")
		statusOnly, _ := cmd.Flags().GetBool("status-only")
		outputPath, _ := cmd.Flags().GetString("output")
		accessReason, _ := cmd.Flags().GetString("reason")
		noConfirm, _ := cmd.Flags().GetBool("no-confirm")

		// Configure read options
		options := vault.DefaultReadInitOptions()
		options.RedactSensitive = !noRedact
		options.ExportFormat = exportFormat
		options.OutputPath = outputPath
		options.AccessReason = accessReason
		options.RequireConfirm = !noConfirm
		options.IncludeStatus = true

		// Handle status-only mode
		if statusOnly {
			options.RedactSensitive = true
			options.RequireConfirm = false
		}

		log.Info(" Starting secure vault init inspection",
			zap.Bool("redacted", options.RedactSensitive),
			zap.String("format", options.ExportFormat),
			zap.Bool("status_only", statusOnly))

		// Perform secure read
		info, err := vault.SecureReadVaultInit(rc, options)
		if err != nil {
			return logger.LogErrAndWrap(rc, "secure vault init read failed", err)
		}

		// Handle different output formats
		switch options.ExportFormat {
		case "json":
			return vault.ExportToJSON(rc, info, options)
		case "secure":
			return vault.ExportToSecureFile(rc, info, options)
		default:
			// Display to console
			if statusOnly {
				return vault.DisplayStatusOnly(rc, info)
			}
			return vault.DisplayVaultInitInfo(rc, info, options)
		}
	}),
}

// InspectVaultCmd lists secrets stored in Vault
var InspectVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Inspect Vault secrets and status",
	Long: `Lists secrets and paths stored in Vault with comprehensive status information.

This command provides:
- Current Vault server status
- List of secret mounts and paths
- Health check results
- Authentication status

Available subcommands:
  agent       - Check Vault Agent status
  ldap        - View LDAP configuration in Vault
  vault-init  - Inspect Vault initialization data

Examples:
  eos read vault              # Show Vault status and available paths
  eos read vault agent        # Check Vault Agent status
  eos read vault ldap         # View LDAP config
  eos read vault-init         # Inspect initialization data`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		log.Info("Starting Vault inspection")

		// ASSESS: Check Vault availability
		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			vaultAddr = "http://127.0.0.1:8200"
		}

		log.Info("Checking Vault status",
			zap.String("vault_addr", vaultAddr))

		// Get Vault client
		client, err := vault.GetVaultClient(rc)
		if err != nil {
			return fmt.Errorf("failed to get Vault client: %w", err)
		}

		// INTERVENE: Get Vault health and status
		health, err := client.Sys().Health()
		if err != nil {
			log.Warn("Failed to get Vault health", zap.Error(err))
		} else {
			log.Info("Vault Health Status",
				zap.Bool("initialized", health.Initialized),
				zap.Bool("sealed", health.Sealed),
				zap.String("version", health.Version),
				zap.String("cluster_name", health.ClusterName))
		}

		// Check if we're authenticated
		token := os.Getenv("VAULT_TOKEN")
		if token == "" {
			log.Info("No VAULT_TOKEN set. Authentication may be required.")
		}

		// Try to list secret mounts
		log.Info("Listing secret engine mounts")
		mounts, err := client.Sys().ListMounts()
		if err != nil {
			log.Warn("Failed to list mounts (may need authentication)", zap.Error(err))
			log.Info("Available subcommands:")
			log.Info("  eos read vault agent       - Check Vault Agent status")
			log.Info("  eos read vault ldap        - View LDAP configuration")
			log.Info("  eos read vault-init        - Inspect initialization data")
			return nil
		}

		log.Info("Secret Engine Mounts")
		for path, mount := range mounts {
			log.Info("Mount",
				zap.String("path", path),
				zap.String("type", mount.Type),
				zap.String("description", mount.Description))

			// Try to list secrets at this mount (only for KV engines)
			if mount.Type == "kv" || mount.Type == "generic" {
				secrets, err := client.Logical().List(path)
				if err != nil {
					log.Debug("Could not list secrets at mount", zap.String("path", path))
					continue
				}

				if secrets != nil && secrets.Data != nil {
					if keys, ok := secrets.Data["keys"].([]interface{}); ok {
						log.Info("Secrets in mount",
							zap.String("path", path),
							zap.Int("count", len(keys)))
						for _, key := range keys {
							log.Info("  Secret key", zap.String("key", fmt.Sprintf("%v", key)))
						}
					}
				}
			}
		}

		// EVALUATE: Summary
		log.Info("Vault inspection completed successfully")
		log.Info("Use subcommands for detailed information:")
		log.Info("  eos read vault agent       - Agent status")
		log.Info("  eos read vault ldap        - LDAP config")
		log.Info("  eos read vault-init        - Init data")

		return nil
	}),
}

// InspectVaultAgentCmd checks Vault Agent status and basic functionality
var InspectVaultAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Check Vault Agent comprehensive status and functionality",
	Long: `Provides comprehensive status information about Vault Agent including:
  • Service status and health
  • Token availability and validity
  • Configuration validation
  • Monitoring status

Examples:
  eos read vault agent          # Full status check
  eos read vault agent --json   # JSON output for automation`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)
		jsonOutput, _ := cmd.Flags().GetBool("json")

		// Get comprehensive agent status
		status, err := vault.GetAgentStatus(rc)
		if err != nil {
			return fmt.Errorf("failed to get agent status: %w", err)
		}

		if jsonOutput {
			// Output JSON for automation
			data, err := json.MarshalIndent(status, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal status: %w", err)
			}
			log.Info("Vault Agent Status JSON", zap.String("json", string(data)))
			return nil
		}

		// Display human-readable status
		vault.DisplayAgentStatus(rc, status)

		// Handle different health statuses appropriately
		switch status.HealthStatus {
		case "healthy":
			log.Info(" Vault Agent is healthy and functioning correctly")
		case "degraded":
			log.Warn("Vault Agent is degraded but operational", zap.String("status", status.HealthStatus))
			// Degraded is informational - agent is running but has minor issues
		case "unhealthy":
			log.Error(" Vault Agent is unhealthy", zap.String("status", status.HealthStatus))
			return fmt.Errorf("vault agent status: %s", status.HealthStatus)
		default:
			log.Warn("❓ Vault Agent has unknown status", zap.String("status", status.HealthStatus))
		}

		return nil
	}),
}

// InspectVaultLDAPCmd views LDAP config stored in Vault
var InspectVaultLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "View stored LDAP config in Vault",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		cfg := &ldap.LDAPConfig{}

		err := vault.ReadFromVaultAt(rc, shared.LDAPVaultMount, shared.LDAPVaultPath, cfg)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to load LDAP config from Vault", zap.Error(err))
			return fmt.Errorf("could not load LDAP config from Vault: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info("LDAP Config Retrieved",
			zap.String("fqdn", cfg.FQDN),
			zap.String("bind_dn", cfg.BindDN),
			zap.String("user_base", cfg.UserBase),
			zap.String("role_base", cfg.RoleBase),
			zap.String("admin_role", cfg.AdminRole),
			zap.String("readonly_role", cfg.ReadonlyRole),
			zap.String("password", crypto.Redact(cfg.Password)),
		)
		return nil
	}),
}

var InspectSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "List and view Eos secrets (redacted)",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		files, err := os.ReadDir(shared.SecretsDir)
		if err != nil {
			return logger.LogErrAndWrap(rc, "inspect secrets: read secrets dir", err)
		}

		if len(files) == 0 {
			log.Info("No secrets found", zap.String("directory", shared.SecretsDir))
			return nil
		}

		log.Info(" Eos Secrets Directory", zap.String("directory", shared.SecretsDir))

		for _, file := range files {
			path := filepath.Join(shared.SecretsDir, file.Name())

			data, err := os.ReadFile(path)
			if err != nil {
				log.Warn(" Failed to read secret file", zap.String("path", path), zap.Error(err))
				continue
			}

			var content map[string]any
			if err := json.Unmarshal(data, &content); err != nil {
				log.Warn(" Failed to parse JSON secret", zap.String("path", path), zap.Error(err))
				log.Warn("Unreadable JSON file", zap.String("file", file.Name()))
				continue
			}

			log.Info(" Secret file", zap.String("file", file.Name()))
			for k, v := range content {
				valStr := fmt.Sprintf("%v", v)
				if strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "key") {
					valStr = crypto.Redact(valStr)
				}
				log.Info("Secret field", zap.String("key", k), zap.String("value", valStr))
			}
		}

		log.Info(" Secrets inspection complete")
		return nil
	}),
}

// All helper functions have been migrated to pkg/vault/export_display.go
