// pkg/vault/security_warnings.go

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecurityWarningLevel indicates severity of security warnings
type SecurityWarningLevel int

const (
	SecurityWarningCritical SecurityWarningLevel = iota
	SecurityWarningHigh
	SecurityWarningMedium
	SecurityWarningLow
)

// SecurityWarning represents a single security warning
type SecurityWarning struct {
	Level       SecurityWarningLevel
	Title       string
	Description string
	Remediation string
}

// DisplaySecurityWarnings shows comprehensive security warnings after Vault installation
// This implements P0 requirement from audit: warn about insecure Shamir key storage
func DisplaySecurityWarnings(rc *eos_io.RuntimeContext, vaultInitPath string) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔒 Displaying security warnings")

	warnings := []SecurityWarning{
		{
			Level: SecurityWarningCritical,
			Title: "INSECURE KEY STORAGE (DEVELOPMENT ONLY)",
			Description: fmt.Sprintf(
				"Vault unseal keys and root token are stored UNENCRYPTED in:\n"+
					"    %s\n\n"+
					"This violates Shamir's Secret Sharing security model!\n"+
					"Keys should be distributed to separate trusted parties, NOT stored together.",
				vaultInitPath,
			),
			Remediation: "For PRODUCTION:\n" +
				"  1. Export keys: sudo eos read vault-init\n" +
				"  2. Distribute unseal keys to 3-5 separate trusted administrators\n" +
				"  3. Store each key in separate encrypted password managers\n" +
				"  4. DELETE the vault_init.json file: sudo rm " + vaultInitPath + "\n" +
				"  5. NEVER store all keys together again",
		},
		{
			Level: SecurityWarningHigh,
			Title: "ROOT TOKEN EXPOSURE",
			Description: "The root token provides UNLIMITED access to Vault.\n" +
				"It should NEVER be used for daily operations.",
			Remediation: "For PRODUCTION:\n" +
				"  1. Create limited-privilege tokens for applications\n" +
				"  2. Use AppRole for service authentication\n" +
				"  3. Revoke the root token: vault token revoke <root-token>\n" +
				"  4. Generate new root token only when absolutely necessary",
		},
		{
			Level: SecurityWarningHigh,
			Title: "FILE SYSTEM ACCESS",
			Description: fmt.Sprintf(
				"Anyone with sudo/root access can read:\n"+
					"    %s\n"+
					"This means all Vault data is accessible to system administrators.",
				shared.VaultDataPath,
			),
			Remediation: "For PRODUCTION:\n" +
				"  1. Use Vault Enterprise with HSM integration\n" +
				"  2. Enable audit logging to detect unauthorized access\n" +
				"  3. Implement strict sudo access controls\n" +
				"  4. Consider using Vault's auto-unseal with cloud KMS",
		},
		{
			Level: SecurityWarningMedium,
			Title: "BACKUP AND DISASTER RECOVERY",
			Description: "Without proper backups, you may lose all Vault data.\n" +
				"Without stored unseal keys, recovery is IMPOSSIBLE.",
			Remediation: "BEFORE using in production:\n" +
				"  1. Implement automated Vault snapshots\n" +
				"  2. Test disaster recovery procedures\n" +
				"  3. Document unseal key recovery process\n" +
				"  4. Store encrypted backups off-site",
		},
		{
			Level: SecurityWarningMedium,
			Title: "NETWORK SECURITY",
			Description: fmt.Sprintf(
				"Vault is listening on: %s\n"+
					"Ensure proper firewall rules are configured.",
				shared.GetVaultAddr(),
			),
			Remediation: "Security checklist:\n" +
				"  1. Verify TLS is enabled (check vault.hcl)\n" +
				"  2. Restrict network access to authorized hosts only\n" +
				"  3. Use mTLS for client authentication if possible\n" +
				"  4. Enable audit logging for all API access",
		},
	}

	// Display warnings to stderr for visibility
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "╔═══════════════════════════════════════════════════════════════════════════════╗")
	_, _ = fmt.Fprintln(os.Stderr, "║                          🔐 SECURITY WARNINGS 🔐                              ║")
	_, _ = fmt.Fprintln(os.Stderr, "╚═══════════════════════════════════════════════════════════════════════════════╝")
	_, _ = fmt.Fprintln(os.Stderr, "")

	for i, warning := range warnings {
		displayWarning(warning, i+1, len(warnings))
	}

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "╔═══════════════════════════════════════════════════════════════════════════════╗")
	_, _ = fmt.Fprintln(os.Stderr, "║  CURRENT CONFIGURATION IS FOR DEVELOPMENT/TESTING ONLY                        ║")
	_, _ = fmt.Fprintln(os.Stderr, "║  DO NOT USE IN PRODUCTION WITHOUT IMPLEMENTING ABOVE RECOMMENDATIONS          ║")
	_, _ = fmt.Fprintln(os.Stderr, "╚═══════════════════════════════════════════════════════════════════════════════╝")
	_, _ = fmt.Fprintln(os.Stderr, "")

	log.Info("🔒 Security warnings displayed",
		zap.Int("warning_count", len(warnings)),
		zap.String("init_file", vaultInitPath))
}

// displayWarning formats and displays a single security warning
func displayWarning(warning SecurityWarning, num, total int) {
	levelIcon := getWarningIcon(warning.Level)
	levelText := getWarningLevelText(warning.Level)

	_, _ = fmt.Fprintf(os.Stderr, "┌─ Warning %d/%d: %s %s ─────────────────────────────────\n", num, total, levelIcon, levelText)
	_, _ = fmt.Fprintf(os.Stderr, "│\n")
	_, _ = fmt.Fprintf(os.Stderr, "│ %s\n", warning.Title)
	_, _ = fmt.Fprintf(os.Stderr, "│\n")

	// Description (word-wrapped)
	for _, line := range wrapText(warning.Description, 75) {
		_, _ = fmt.Fprintf(os.Stderr, "│ %s\n", line)
	}

	_, _ = fmt.Fprintf(os.Stderr, "│\n")
	_, _ = fmt.Fprintf(os.Stderr, "│ REMEDIATION:\n")

	// Remediation steps
	for _, line := range wrapText(warning.Remediation, 75) {
		_, _ = fmt.Fprintf(os.Stderr, "│ %s\n", line)
	}

	_, _ = fmt.Fprintf(os.Stderr, "└────────────────────────────────────────────────────────────────────────────────\n")
	_, _ = fmt.Fprintln(os.Stderr, "")
}

// getWarningIcon returns the appropriate icon for warning level
func getWarningIcon(level SecurityWarningLevel) string {
	switch level {
	case SecurityWarningCritical:
		return "🚨"
	case SecurityWarningHigh:
		return " "
	case SecurityWarningMedium:
		return "⚡"
	case SecurityWarningLow:
		return " "
	default:
		return "❓"
	}
}

// getWarningLevelText returns human-readable warning level
func getWarningLevelText(level SecurityWarningLevel) string {
	switch level {
	case SecurityWarningCritical:
		return "CRITICAL"
	case SecurityWarningHigh:
		return "HIGH"
	case SecurityWarningMedium:
		return "MEDIUM"
	case SecurityWarningLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// wrapText wraps text to specified width, preserving existing line breaks
func wrapText(text string, width int) []string {
	var result []string

	// Split by existing newlines first
	lines := []string{}
	currentLine := ""
	for _, r := range text {
		if r == '\n' {
			lines = append(lines, currentLine)
			currentLine = ""
		} else {
			currentLine += string(r)
		}
	}
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	// Wrap each line if needed
	for _, line := range lines {
		if len(line) <= width {
			result = append(result, line)
			continue
		}

		// Word wrap
		words := []string{}
		word := ""
		for _, r := range line {
			if r == ' ' {
				if word != "" {
					words = append(words, word)
					word = ""
				}
			} else {
				word += string(r)
			}
		}
		if word != "" {
			words = append(words, word)
		}

		wrapped := ""
		for _, w := range words {
			if len(wrapped)+len(w)+1 > width {
				result = append(result, wrapped)
				wrapped = w
			} else {
				if wrapped != "" {
					wrapped += " " + w
				} else {
					wrapped = w
				}
			}
		}
		if wrapped != "" {
			result = append(result, wrapped)
		}
	}

	return result
}

// DisplayPostInstallSecurityChecklist shows a checklist for post-installation security
func DisplayPostInstallSecurityChecklist(rc *eos_io.RuntimeContext) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("📋 Displaying post-install security checklist")

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "╔═══════════════════════════════════════════════════════════════════════════════╗")
	_, _ = fmt.Fprintln(os.Stderr, "║                    📋 POST-INSTALLATION SECURITY CHECKLIST                    ║")
	_, _ = fmt.Fprintln(os.Stderr, "╚═══════════════════════════════════════════════════════════════════════════════╝")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Before using Vault in production, complete these steps:")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [ ] 1. Verify TLS is enabled and working")
	_, _ = fmt.Fprintln(os.Stderr, "      └─ Run: eos validate vault")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [ ] 2. Export and distribute unseal keys")
	_, _ = fmt.Fprintln(os.Stderr, "      └─ Run: sudo eos read vault-init")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [ ] 3. Delete vault_init.json after distributing keys")
	_, _ = fmt.Fprintln(os.Stderr, "      └─ Run: sudo rm /var/lib/eos/secret/vault_init.json")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [ ] 4. Enable audit logging")
	_, _ = fmt.Fprintln(os.Stderr, "      └─ Vault maintains audit logs at: /var/log/vault/vault-audit.log")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [ ] 5. Configure firewall rules")
	_, _ = fmt.Fprintln(os.Stderr, "      └─ Restrict access to Vault port 8179")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [ ] 6. Set up automated backups")
	_, _ = fmt.Fprintln(os.Stderr, "      └─ Document: https://wiki.cybermonkey.net.au")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [ ] 7. Test disaster recovery procedures")
	_, _ = fmt.Fprintln(os.Stderr, "      └─ Ensure you can unseal Vault with distributed keys")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [ ] 8. Revoke root token after initial setup")
	_, _ = fmt.Fprintln(os.Stderr, "      └─ Generate new root token only when needed")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "╚═══════════════════════════════════════════════════════════════════════════════╝")
	_, _ = fmt.Fprintln(os.Stderr, "")

	log.Info("📋 Security checklist displayed")
}

// ValidateSecurityPosture performs basic security posture checks
func ValidateSecurityPosture(rc *eos_io.RuntimeContext) ([]string, []string) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Validating security posture")

	var passed []string
	var failed []string

	// Check 1: Vault init file should be deleted in production
	if _, err := os.Stat(shared.VaultInitPath); err == nil {
		failed = append(failed, "vault_init.json still exists - should be deleted after key distribution")
	} else if os.IsNotExist(err) {
		passed = append(passed, "vault_init.json properly deleted")
	}

	// Check 2: TLS cert/key should exist
	tlsCertPath := "/opt/vault/tls/vault.crt"
	tlsKeyPath := "/opt/vault/tls/vault.key"
	if _, err := os.Stat(tlsCertPath); err == nil {
		passed = append(passed, "TLS certificate exists")
	} else {
		failed = append(failed, "TLS certificate not found - TLS may be disabled")
	}

	if info, err := os.Stat(tlsKeyPath); err == nil {
		if info.Mode().Perm() == 0600 {
			passed = append(passed, "TLS key has correct permissions (0600)")
		} else {
			failed = append(failed, fmt.Sprintf("TLS key has insecure permissions: %o (should be 0600)", info.Mode().Perm()))
		}
	} else {
		failed = append(failed, "TLS key not found - TLS may be disabled")
	}

	// Check 3: Audit log should exist if audit is enabled
	auditLogPath := "/var/log/vault/vault-audit.log"
	if _, err := os.Stat(auditLogPath); err == nil {
		passed = append(passed, "Audit logging is configured")
	} else {
		failed = append(failed, "Audit log not found - audit logging may not be enabled")
	}

	log.Info(" Security posture validation completed",
		zap.Int("passed", len(passed)),
		zap.Int("failed", len(failed)))

	return passed, failed
}
