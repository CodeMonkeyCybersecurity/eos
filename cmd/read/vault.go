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
	InspectVaultCmd.AddCommand(InspectVaultAgentCmd)
	InspectVaultCmd.AddCommand(InspectVaultLDAPCmd)
	ReadCmd.AddCommand(InspectVaultCmd)
	ReadCmd.AddCommand(InspectVaultInitCmd)
	
	// Add flags for enhanced vault-init command
	InspectVaultInitCmd.Flags().Bool("no-redact", false, "Show sensitive data in plaintext (requires confirmation)")
	InspectVaultInitCmd.Flags().String("export", "console", "Export format: console, json, secure")
	InspectVaultInitCmd.Flags().Bool("status-only", false, "Show only Vault status information (no sensitive data)")
	InspectVaultInitCmd.Flags().String("output", "", "Output file path for export formats")
	InspectVaultInitCmd.Flags().String("reason", "", "Access reason for audit logging")
	InspectVaultInitCmd.Flags().Bool("no-confirm", false, "Skip confirmation prompts (use with caution)")
	
	// Add flags for vault agent command
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

		log.Info("🔍 Starting secure vault init inspection",
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
			return exportToJSON(info, options)
		case "secure":
			return exportToSecureFile(info, options)
		default:
			// Display to console
			if statusOnly {
				return displayStatusOnly(info)
			}
			return vault.DisplayVaultInitInfo(info, options)
		}
	}),
}

// InspectVaultCmd lists secrets stored in Vault
var InspectVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Inspect current Vault paths (requires root or eos)",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		log.Info("Listing secrets under secret/eos")
		entries, err := vault.ListUnder(rc, shared.EosID)
		if err != nil {
			log.Error("Failed to list Vault secrets", zap.Error(err))
			return fmt.Errorf("could not list Vault contents: %w", err)
		}

		for _, entry := range entries {
			log.Info("Found Vault entry", zap.String("entry", "secret/eos/"+strings.TrimSuffix(entry, "/")))
		}

		log.Info("Vault entries inspection complete", zap.Int("count", len(entries)))
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
			fmt.Print(string(data))
			return nil
		}

		// Display human-readable status
		displayAgentStatus(status)

		if status.HealthStatus == "healthy" {
			log.Info("✅ Vault Agent is healthy and functioning correctly")
		} else {
			log.Warn("⚠️ Vault Agent has issues", zap.String("status", status.HealthStatus))
			return fmt.Errorf("vault agent status: %s", status.HealthStatus)
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
			fmt.Println("❌ No secrets found in", shared.SecretsDir)
			return nil
		}

		fmt.Println("\n🔐 Eos Secrets Directory")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		for _, file := range files {
			path := filepath.Join(shared.SecretsDir, file.Name())

			data, err := os.ReadFile(path)
			if err != nil {
				log.Warn("❌ Failed to read secret file", zap.String("path", path), zap.Error(err))
				continue
			}

			var content map[string]interface{}
			if err := json.Unmarshal(data, &content); err != nil {
				log.Warn("❌ Failed to parse JSON secret", zap.String("path", path), zap.Error(err))
				fmt.Printf("- %s (Unreadable JSON)\n", file.Name())
				continue
			}

			fmt.Printf("\n📄 File: %s\n", file.Name())
			for k, v := range content {
				valStr := fmt.Sprintf("%v", v)
				if strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "key") {
					valStr = crypto.Redact(valStr)
				}
				fmt.Printf("    %s: %s\n", k, valStr)
			}
		}

		fmt.Println("\n✅ Secrets inspection complete.")
		return nil
	}),
}

// Helper functions for the new export features

func exportToJSON(info *vault.VaultInitInfo, options *vault.ReadInitOptions) error {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if options.OutputPath != "" {
		return os.WriteFile(options.OutputPath, data, 0600)
	}
	
	fmt.Print(string(data))
	return nil
}

func exportToSecureFile(info *vault.VaultInitInfo, options *vault.ReadInitOptions) error {
	if options.OutputPath == "" {
		return fmt.Errorf("output path required for secure export")
	}

	// Create secure directory
	dir := filepath.Dir(options.OutputPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Marshal with indentation
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write with secure permissions
	if err := os.WriteFile(options.OutputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write secure file: %w", err)
	}

	fmt.Printf("✅ Vault init data exported securely to: %s\n", options.OutputPath)
	return nil
}

func displayStatusOnly(info *vault.VaultInitInfo) error {
	fmt.Println("\n🔍 Vault Status Overview")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Display file information
	if info.FileInfo != nil {
		fmt.Printf("\n📄 Init File: %s\n", info.FileInfo.Path)
		fmt.Printf("   Exists: %v\n", info.FileInfo.Exists)
		fmt.Printf("   Readable: %v\n", info.FileInfo.Readable)
		if info.FileInfo.Exists {
			fmt.Printf("   Size: %d bytes\n", info.FileInfo.Size)
			fmt.Printf("   Modified: %s\n", info.FileInfo.ModTime.Format("2006-01-02 15:04:05"))
		}
	}

	// Display Vault status
	if info.VaultStatus != nil {
		fmt.Printf("\n🏛️ Vault Status\n")
		fmt.Printf("   Address: %s\n", info.VaultStatus.Address)
		fmt.Printf("   Running: %v\n", info.VaultStatus.Running)
		fmt.Printf("   Reachable: %v\n", info.VaultStatus.Reachable)
		fmt.Printf("   Initialized: %v\n", info.VaultStatus.Initialized)
		fmt.Printf("   Sealed: %v\n", info.VaultStatus.Sealed)
		fmt.Printf("   Health: %s\n", info.VaultStatus.HealthStatus)
	}

	// Display security status
	if info.SecurityStatus != nil {
		fmt.Printf("\n🛡️ Security Status\n")
		fmt.Printf("   MFA Enabled: %v\n", info.SecurityStatus.MFAEnabled)
		fmt.Printf("   Audit Enabled: %v\n", info.SecurityStatus.AuditEnabled)
		fmt.Printf("   Hardening Applied: %v\n", info.SecurityStatus.HardeningApplied)
		fmt.Printf("   Auth Methods: %d\n", len(info.SecurityStatus.AuthMethods))
	}

	fmt.Println("\n💡 Use --no-redact flag to view sensitive initialization data")
	return nil
}

// displayAgentStatus provides human-readable display of Vault Agent status
func displayAgentStatus(status *vault.AgentStatus) {
	fmt.Println("\n🤖 Vault Agent Status")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Service status
	if status.ServiceRunning {
		fmt.Println("✅ Service: Running")
	} else {
		fmt.Println("❌ Service: Not Running")
	}

	// Token status
	if status.TokenAvailable {
		fmt.Println("✅ Token: Available")
		if !status.LastTokenTime.IsZero() {
			fmt.Printf("   Last Updated: %s\n", status.LastTokenTime.Format("2006-01-02 15:04:05"))
		}
		if status.TokenValid {
			fmt.Println("✅ Token: Valid")
		} else {
			fmt.Println("⚠️ Token: Invalid or Empty")
		}
	} else {
		fmt.Println("❌ Token: Not Available")
	}

	// Configuration status
	if status.ConfigValid {
		fmt.Println("✅ Configuration: Valid")
	} else {
		fmt.Println("❌ Configuration: Missing or Invalid")
	}

	// Overall health
	fmt.Printf("\n🏥 Overall Health: ")
	switch status.HealthStatus {
	case "healthy":
		fmt.Println("✅ Healthy")
	case "degraded":
		fmt.Println("⚠️ Degraded")
	case "unhealthy":
		fmt.Println("❌ Unhealthy")
	default:
		fmt.Printf("❓ Unknown (%s)\n", status.HealthStatus)
	}

	// Recommendations
	if status.HealthStatus != "healthy" {
		fmt.Println("\n💡 Recommendations:")
		if !status.ServiceRunning {
			fmt.Println("   • Start the service: sudo systemctl start vault-agent")
		}
		if !status.TokenAvailable || !status.TokenValid {
			fmt.Println("   • Check agent authentication: journalctl -u vault-agent")
		}
		if !status.ConfigValid {
			fmt.Println("   • Verify configuration: eos enable vault")
		}
	}
}