// pkg/debug/vault/diag_service.go
// Vault systemd service diagnostic checks
//
// This module contains diagnostics for the main vault.service systemd unit:
// - SystemdServiceDiagnostic: Service status and health
// - ServiceConfigDiagnostic: User/Group configuration from systemd unit file
// - ServiceLogsDiagnostic: Recent logs with permission error detection
//
// Note: This is separate from Vault Agent diagnostics (VaultAgentServiceDiagnostic, etc.)
// which are for the vault-agent-eos.service unit.

package vault

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceDiagnostics returns all vault service diagnostic checks
func ServiceDiagnostics() []*debug.Diagnostic {
	return []*debug.Diagnostic{
		SystemdServiceDiagnostic(),
		ServiceConfigDiagnostic(), // NEW: Show User=/Group= from systemd
		ServiceLogsDiagnostic(),
	}
}

// SystemdServiceDiagnostic checks the systemd service status
func SystemdServiceDiagnostic() *debug.Diagnostic {
	return debug.SystemdServiceCheck("vault")
}

// ServiceConfigDiagnostic shows the systemd service User and Group configuration
func ServiceConfigDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Systemd Service Configuration",
		Category:    "Systemd",
		Description: "Show User= and Group= configuration from vault.service",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("=== Systemd Service Configuration ===\n\n")

			// Run systemctl cat to show full service file
			catCmd := exec.CommandContext(ctx, "systemctl", "cat", "vault.service")
			catOutput, catErr := catCmd.CombinedOutput()

			if catErr != nil {
				output.WriteString("ERROR: Could not read vault.service configuration\n")
				output.WriteString(fmt.Sprintf("Command output: %s\n", string(catOutput)))
				result.Status = debug.StatusError
				result.Message = "Vault service file not found"
				result.Remediation = "Install vault service: sudo eos create vault"
				result.Output = output.String()
				return result, nil
			}

			// Show full service file
			output.WriteString("Full Service File:\n")
			output.WriteString("─────────────────────────────────────────────────────────────\n")
			output.WriteString(string(catOutput))
			output.WriteString("\n")

			// Extract and highlight User= and Group= lines
			output.WriteString("Key Configuration:\n")
			output.WriteString("─────────────────────────────────────────────────────────────\n")

			lines := strings.Split(string(catOutput), "\n")
			foundUser := false
			foundGroup := false
			var user, group string

			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "User=") {
					output.WriteString(fmt.Sprintf("  %s\n", trimmed))
					user = strings.TrimPrefix(trimmed, "User=")
					result.Metadata["user"] = user
					foundUser = true
				} else if strings.HasPrefix(trimmed, "Group=") {
					output.WriteString(fmt.Sprintf("  %s\n", trimmed))
					group = strings.TrimPrefix(trimmed, "Group=")
					result.Metadata["group"] = group
					foundGroup = true
				}
			}

			if !foundUser {
				output.WriteString("  ⚠ WARNING: No User= directive found (will run as root!)\n")
				result.Status = debug.StatusWarning
				result.Message = "Service not configured to run as vault user"
				result.Remediation = "Add 'User=vault' to [Service] section of vault.service"
			}

			if !foundGroup {
				output.WriteString("  ⚠ WARNING: No Group= directive found\n")
			}

			// Verify the user exists
			if foundUser && user != "" {
				idCmd := exec.CommandContext(ctx, "id", user)
				idOutput, idErr := idCmd.CombinedOutput()
				output.WriteString("\nUser Verification:\n")
				if idErr != nil {
					output.WriteString(fmt.Sprintf("  ✗ User '%s' does not exist!\n", user))
					result.Status = debug.StatusError
					result.Message = fmt.Sprintf("Configured user '%s' does not exist", user)
					result.Remediation = fmt.Sprintf("Create user: sudo useradd -r -s /bin/false %s", user)
				} else {
					output.WriteString(fmt.Sprintf("  ✓ User '%s' exists: %s\n", user, strings.TrimSpace(string(idOutput))))
				}
			}

			if result.Status == "" {
				result.Status = debug.StatusOK
				result.Message = "Service configured correctly"
			}

			result.Output = output.String()
			return result, nil
		},
	}
}

// ServiceLogsDiagnostic retrieves recent service logs
func ServiceLogsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Service Logs",
		Category:    "Systemd",
		Description: "Recent vault service logs with permission error detection",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Retrieving and analyzing Vault service logs")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, "journalctl", "-u", "vault.service", "-n", "100", "--no-pager")
			output, err := cmd.CombinedOutput()

			outputStr := string(output)

			// Count permission denied errors (the bug we're looking for!)
			permDeniedCount := strings.Count(strings.ToLower(outputStr), "permission denied")
			logger.Info("Analyzed service logs for permission errors",
				zap.Int("permission_denied_count", permDeniedCount),
				zap.Int("log_lines", strings.Count(outputStr, "\n")))

			var enhancedOutput strings.Builder
			enhancedOutput.WriteString("=== Vault Service Logs (last 100 lines) ===\n\n")

			// If permission errors found, highlight them at the top
			if permDeniedCount > 0 {
				logger.Error("CRITICAL: Permission denied errors found in service logs",
					zap.Int("error_count", permDeniedCount))
				enhancedOutput.WriteString(fmt.Sprintf("  CRITICAL: Found %d 'permission denied' errors!\n", permDeniedCount))
				enhancedOutput.WriteString("This indicates the vault user cannot access required directories.\n")
				enhancedOutput.WriteString("This is typically caused by /opt/vault having wrong permissions/ownership.\n\n")

				// Extract just the permission denied lines
				enhancedOutput.WriteString("Permission Denied Errors:\n")
				enhancedOutput.WriteString("─────────────────────────────────────────────────────────────\n")
				lines := strings.Split(outputStr, "\n")
				count := 0
				for _, line := range lines {
					if strings.Contains(strings.ToLower(line), "permission denied") {
						enhancedOutput.WriteString(line)
						enhancedOutput.WriteString("\n")
						count++
						if count >= 5 { // Show first 5, then summarize
							if permDeniedCount > 5 {
								enhancedOutput.WriteString(fmt.Sprintf("... and %d more similar errors\n", permDeniedCount-5))
							}
							break
						}
					}
				}
				enhancedOutput.WriteString("\n")
			}

			// Add full log output
			enhancedOutput.WriteString("Full Log Output:\n")
			enhancedOutput.WriteString("─────────────────────────────────────────────────────────────\n")
			enhancedOutput.WriteString(outputStr)

			result.Output = enhancedOutput.String()
			result.Metadata["permission_denied_count"] = permDeniedCount

			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Could not retrieve logs"
			} else if permDeniedCount > 0 {
				// CRITICAL: Permission errors found
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("CRITICAL: %d permission denied errors (see Permissions diagnostic)", permDeniedCount)
				result.Remediation = "Fix parent directory permissions:\n" +
					"  sudo chown vault:vault /opt/vault\n" +
					"  sudo chmod 755 /opt/vault\n" +
					"  sudo systemctl restart vault\n" +
					"Run 'sudo eos debug vault' for detailed permission analysis"
			} else {
				// Check for other errors in logs
				if strings.Contains(outputStr, "error") || strings.Contains(outputStr, "Error") {
					result.Status = debug.StatusWarning
					result.Message = "Logs contain errors (see output)"
				} else {
					result.Status = debug.StatusInfo
					result.Message = "Logs retrieved successfully, no critical errors"
				}
			}

			return result, nil
		},
	}
}
