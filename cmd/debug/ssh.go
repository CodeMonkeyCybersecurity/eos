// cmd/debug/ssh.go
// SSH diagnostics command for troubleshooting SSH connectivity

package debug

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ssh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	sshDebugFormat            string
	sshDebugClientOnly        bool
	sshDebugKeyPath           string
	sshDebugSanitize          bool
	sshDebugTestForwarding    bool
	sshDebugHost              string
	sshDebugUser              string
	sshDebugPort              string
	sshDebugPassword          string
	sshDebugForwardTestTarget string
)

var sshDebugCmd = &cobra.Command{
	Use:   "ssh [user@host]",
	Short: "Comprehensive SSH diagnostics and troubleshooting",
	Long: `Collect and analyze comprehensive SSH diagnostic information.

This command performs extensive checks on:

CLIENT-SIDE DIAGNOSTICS:
- SSH key existence (ED25519, RSA, ECDSA)
- Key permissions and fingerprints
- SSH agent status and loaded keys
- Public key content for server copying

SERVER-SIDE DIAGNOSTICS (when target provided):
- ~/.ssh directory permissions (should be 700)
- ~/.ssh/authorized_keys permissions (should be 600 or 644)
- File ownership verification
- Home directory permissions
- Authorized keys count and fingerprints
- sshd_config settings (PubkeyAuthentication, AuthorizedKeysFile)
- Recent SSH authentication logs

USAGE EXAMPLES:
  # Client-side diagnostics only
  eos debug ssh --client-only

  # Full diagnostics (client + server)
  eos debug ssh user@host

  # Full diagnostics with custom SSH key
  eos debug ssh user@host --key ~/.ssh/custom_id_ed25519

  # JSON format for automation
  eos debug ssh user@host --format=json

  # Markdown format for GitHub issues
  eos debug ssh user@host --format=markdown

  # Sanitize sensitive data before sharing
  eos debug ssh user@host --sanitize

  # Test that port forwarding is allowed on the target
  eos debug ssh --test-forwarding --host vhost1 --user henry

TROUBLESHOOTING COMMON ISSUES:

1. "Permission denied (publickey)" errors:
   - Check client key exists: eos debug ssh --client-only
   - Verify server permissions: eos debug ssh user@host
   - Look for permission issues in ~/.ssh/ or authorized_keys

2. SSH agent not working:
   - Check agent status in client diagnostics
   - Add key to agent: ssh-add ~/.ssh/id_ed25519

3. Key not found on server:
   - Copy key with: ssh-copy-id user@host
   - Or manually: cat ~/.ssh/id_ed25519.pub | ssh user@host 'cat >> ~/.ssh/authorized_keys'

OUTPUT:
All diagnostics are automatically saved to ~/.eos/debug/eos-debug-ssh-{timestamp}.{ext}
for later analysis or sharing with support.`,

	RunE: eos_cli.WrapDebug("ssh", runSSHDebug),
}

func init() {
	sshDebugCmd.Flags().StringVar(&sshDebugFormat, "format", "text", "Output format: text, json, markdown")
	sshDebugCmd.Flags().BoolVar(&sshDebugClientOnly, "client-only", false, "Run client-side diagnostics only (no server connection)")
	sshDebugCmd.Flags().StringVar(&sshDebugKeyPath, "key", "", "Path to SSH private key (auto-detected if not specified)")
	sshDebugCmd.Flags().BoolVar(&sshDebugSanitize, "sanitize", false, "Redact sensitive information (keys, paths)")
	sshDebugCmd.Flags().BoolVar(&sshDebugTestForwarding, "test-forwarding", false, "Test whether SSH port forwarding is permitted on the target")
	sshDebugCmd.Flags().StringVar(&sshDebugHost, "host", "", "Target host for --test-forwarding (e.g., vhost1 or user@vhost1)")
	sshDebugCmd.Flags().StringVar(&sshDebugUser, "user", "", "SSH username for --test-forwarding")
	sshDebugCmd.Flags().StringVar(&sshDebugPort, "port", "22", "SSH port for --test-forwarding")
	sshDebugCmd.Flags().StringVar(&sshDebugPassword, "password", "", "SSH password for --test-forwarding (optional if key auth works)")
	sshDebugCmd.Flags().StringVar(&sshDebugForwardTestTarget, "forward-target", "127.0.0.1:22", "Destination to probe through the forwarded connection")

	debugCmd.AddCommand(sshDebugCmd)
}

func runSSHDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	if sshDebugTestForwarding {
		return runSSHForwardingTest(rc)
	}

	logger := otelzap.Ctx(rc.Ctx)

	// Determine target (if provided)
	var target string
	if len(args) > 0 {
		target = args[0]
	}

	// Validate flags
	if sshDebugClientOnly && target != "" {
		logger.Warn("Ignoring target when --client-only is specified")
		target = ""
	}

	if target == "" && !sshDebugClientOnly {
		logger.Info("No target specified, running client-side diagnostics only")
		sshDebugClientOnly = true
	}

	logger.Info("Starting SSH diagnostics",
		zap.String("target", target),
		zap.Bool("client_only", sshDebugClientOnly),
		zap.String("format", sshDebugFormat))

	// Run diagnostics
	var report *ssh.SSHDiagnosticReport
	var err error

	if sshDebugClientOnly {
		// Client-only diagnostics (without target-specific checks)
		clientResults, clientErr := ssh.RunClientDiagnostics(rc)
		if clientErr != nil {
			return fmt.Errorf("client diagnostics failed: %w", clientErr)
		}
		report = &ssh.SSHDiagnosticReport{
			ClientResults: clientResults,
			ServerResults: nil,
			TargetHost:    "",
		}
	} else {
		// Full diagnostics (client + server)
		// This includes ssh-copy-id key selection test when target provided
		report, err = ssh.RunFullSSHDiagnostics(rc, target, sshDebugKeyPath)
		if err != nil {
			return fmt.Errorf("SSH diagnostics failed: %w", err)
		}
	}

	// Format output
	output, err := formatSSHDiagnosticReport(report, sshDebugFormat, sshDebugSanitize)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	// Print to stdout
	fmt.Print(output)

	// Automatic capture to file
	captureConfig := &debug.CaptureConfig{
		ServiceName: "ssh",
		Output:      output,
		Format:      sshDebugFormat,
	}

	if filePath, captureErr := debug.CaptureDebugOutput(rc, captureConfig); captureErr != nil {
		logger.Warn("Failed to auto-capture debug output", zap.Error(captureErr))
	} else {
		logger.Info("Debug output automatically saved", zap.String("file", filePath))
	}

	return nil
}

func runSSHForwardingTest(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if sshDebugHost == "" {
		return fmt.Errorf("--host is required when using --test-forwarding")
	}

	connCfg, err := ssh.BuildConnectionConfig(sshDebugHost, sshDebugUser, sshDebugPort, sshDebugKeyPath, sshDebugPassword, "")
	if err != nil {
		return err
	}

	result, err := ssh.TestForwarding(rc, connCfg, sshDebugForwardTestTarget)
	if err != nil {
		return err
	}

	if result.Success {
		logger.Info("SSH port forwarding test passed",
			zap.String("host", connCfg.Host),
			zap.String("user", connCfg.User),
			zap.String("target", result.Target),
			zap.String("message", result.Message))
		return nil
	}

	logger.Warn("SSH port forwarding test failed",
		zap.String("host", connCfg.Host),
		zap.String("user", connCfg.User),
		zap.String("target", result.Target),
		zap.String("message", result.Message))
	return fmt.Errorf("port forwarding blocked: %s", result.Message)
}

// formatSSHDiagnosticReport formats the diagnostic report based on the requested format
func formatSSHDiagnosticReport(report *ssh.SSHDiagnosticReport, format string, sanitize bool) (string, error) {
	switch format {
	case "json":
		return formatSSHReportJSON(report)
	case "markdown", "md":
		return formatSSHReportMarkdown(report, sanitize)
	default: // "text"
		return formatSSHReportText(report, sanitize)
	}
}

// formatSSHReportText formats the report as human-readable text
func formatSSHReportText(report *ssh.SSHDiagnosticReport, sanitize bool) (string, error) {
	var sb strings.Builder

	sb.WriteString("=== SSH Diagnostics Report ===\n\n")

	// Client-side diagnostics
	if len(report.ClientResults) > 0 {
		sb.WriteString("CLIENT-SIDE DIAGNOSTICS:\n")
		sb.WriteString(strings.Repeat("-", 80) + "\n")

		for _, result := range report.ClientResults {
			sb.WriteString(fmt.Sprintf("\n[%s] %s: %s\n",
				getStatusSymbol(result.Status),
				result.Name,
				result.Message))

			if result.Details != "" {
				details := result.Details
				if sanitize {
					details = sanitizeSSHDetails(details)
				}
				sb.WriteString(fmt.Sprintf("  Details:\n%s\n", indentText(details, "    ")))
			}
		}
		sb.WriteString("\n")
	}

	// Server-side diagnostics
	if len(report.ServerResults) > 0 {
		sb.WriteString(fmt.Sprintf("\nSERVER-SIDE DIAGNOSTICS: %s\n", report.TargetHost))
		sb.WriteString(strings.Repeat("-", 80) + "\n")

		for _, result := range report.ServerResults {
			sb.WriteString(fmt.Sprintf("\n[%s] %s: %s\n",
				getStatusSymbol(result.Status),
				result.Name,
				result.Message))

			if result.Details != "" {
				details := result.Details
				if sanitize {
					details = sanitizeSSHDetails(details)
				}
				sb.WriteString(fmt.Sprintf("  Details:\n%s\n", indentText(details, "    ")))
			}
		}
		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString(generateSSHSummary(report))

	return sb.String(), nil
}

// formatSSHReportMarkdown formats the report as markdown
func formatSSHReportMarkdown(report *ssh.SSHDiagnosticReport, sanitize bool) (string, error) {
	var sb strings.Builder

	sb.WriteString("# SSH Diagnostics Report\n\n")

	// Client-side diagnostics
	if len(report.ClientResults) > 0 {
		sb.WriteString("## Client-Side Diagnostics\n\n")

		for _, result := range report.ClientResults {
			sb.WriteString(fmt.Sprintf("### %s %s\n\n", getStatusEmoji(result.Status), result.Name))
			sb.WriteString(fmt.Sprintf("**Status:** %s\n\n", result.Status))
			sb.WriteString(fmt.Sprintf("**Message:** %s\n\n", result.Message))

			if result.Details != "" {
				details := result.Details
				if sanitize {
					details = sanitizeSSHDetails(details)
				}
				sb.WriteString("**Details:**\n```\n")
				sb.WriteString(details)
				sb.WriteString("\n```\n\n")
			}
		}
	}

	// Server-side diagnostics
	if len(report.ServerResults) > 0 {
		sb.WriteString(fmt.Sprintf("## Server-Side Diagnostics: %s\n\n", report.TargetHost))

		for _, result := range report.ServerResults {
			sb.WriteString(fmt.Sprintf("### %s %s\n\n", getStatusEmoji(result.Status), result.Name))
			sb.WriteString(fmt.Sprintf("**Status:** %s\n\n", result.Status))
			sb.WriteString(fmt.Sprintf("**Message:** %s\n\n", result.Message))

			if result.Details != "" {
				details := result.Details
				if sanitize {
					details = sanitizeSSHDetails(details)
				}
				sb.WriteString("**Details:**\n```\n")
				sb.WriteString(details)
				sb.WriteString("\n```\n\n")
			}
		}
	}

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString(generateSSHSummary(report))

	return sb.String(), nil
}

// formatSSHReportJSON formats the report as JSON
func formatSSHReportJSON(report *ssh.SSHDiagnosticReport) (string, error) {
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(jsonData), nil
}

// Helper functions

func getStatusSymbol(status string) string {
	switch status {
	case "pass":
		return "✓"
	case "fail":
		return "✗"
	case "warn":
		return "⚠"
	case "skip":
		return "○"
	default:
		return "?"
	}
}

func getStatusEmoji(status string) string {
	switch status {
	case "pass":
		return "✅"
	case "fail":
		return "❌"
	case "warn":
		return ""
	case "skip":
		return "⏭️"
	default:
		return "❓"
	}
}

func indentText(text, indent string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = indent + line
		}
	}
	return strings.Join(lines, "\n")
}

func sanitizeSSHDetails(details string) string {
	// Redact SSH public keys (keep type and fingerprint, redact key data)
	details = strings.ReplaceAll(details, "ssh-ed25519 AAAA", "ssh-ed25519 [REDACTED]")
	details = strings.ReplaceAll(details, "ssh-rsa AAAA", "ssh-rsa [REDACTED]")
	details = strings.ReplaceAll(details, "ecdsa-sha2-nistp256 AAAA", "ecdsa-sha2-nistp256 [REDACTED]")

	// Redact file paths (keep basename, redact directory)
	// Example: /home/user/.ssh/id_ed25519 -> ~/.ssh/id_ed25519
	lines := strings.Split(details, "\n")
	for i, line := range lines {
		if strings.Contains(line, "/.ssh/") {
			// Replace absolute paths with ~ prefix
			line = strings.ReplaceAll(line, "/home/", "~/")
			line = strings.ReplaceAll(line, "/Users/", "~/")
			lines[i] = line
		}
	}
	details = strings.Join(lines, "\n")

	return details
}

func generateSSHSummary(report *ssh.SSHDiagnosticReport) string {
	var sb strings.Builder

	// Count statuses
	clientPass := countStatus(report.ClientResults, "pass")
	clientFail := countStatus(report.ClientResults, "fail")
	clientWarn := countStatus(report.ClientResults, "warn")

	serverPass := countStatus(report.ServerResults, "pass")
	serverFail := countStatus(report.ServerResults, "fail")
	serverWarn := countStatus(report.ServerResults, "warn")

	sb.WriteString("SUMMARY:\n")

	if len(report.ClientResults) > 0 {
		sb.WriteString(fmt.Sprintf("  Client: %d passed, %d failed, %d warnings\n",
			clientPass, clientFail, clientWarn))
	}

	if len(report.ServerResults) > 0 {
		sb.WriteString(fmt.Sprintf("  Server: %d passed, %d failed, %d warnings\n",
			serverPass, serverFail, serverWarn))
	}

	// Overall status
	totalFail := clientFail + serverFail
	totalWarn := clientWarn + serverWarn

	if totalFail > 0 {
		sb.WriteString("\n⚠ ISSUES DETECTED - Review failed checks above\n")
	} else if totalWarn > 0 {
		sb.WriteString("\n⚠ WARNINGS - Review warnings above\n")
	} else {
		sb.WriteString("\n✓ All checks passed\n")
	}

	return sb.String()
}

func countStatus(results []ssh.SSHDiagnosticResult, status string) int {
	count := 0
	for _, result := range results {
		if result.Status == status {
			count++
		}
	}
	return count
}
