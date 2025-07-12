package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecuritySnapshot takes a security-focused snapshot
// Migrated from cmd/ragequit/ragequit.go securitySnapshot
func SecuritySnapshot(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for security snapshot
	logger.Info("Assessing security snapshot requirements")

	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-security.txt")

	var output strings.Builder
	output.WriteString("=== Security Snapshot ===\n")
	output.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339)))

	// INTERVENE - Collect security information
	logger.Debug("Collecting security information")

	// Current users
	output.WriteString("=== Logged In Users ===\n")
	if whoOutput := system.RunCommandWithTimeout("who", []string{}, 5*time.Second); whoOutput != "" {
		output.WriteString(whoOutput)
		output.WriteString("\n")
	}

	if wOutput := system.RunCommandWithTimeout("w", []string{}, 5*time.Second); wOutput != "" {
		output.WriteString("\n=== User Activity ===\n")
		output.WriteString(wOutput)
		output.WriteString("\n")
	}

	// Last logins
	if lastOutput := system.RunCommandWithTimeout("last", []string{"-20"}, 5*time.Second); lastOutput != "" {
		output.WriteString("\n=== Recent Logins ===\n")
		output.WriteString(lastOutput)
		output.WriteString("\n")
	}

	// Failed login attempts
	if shared.FileExists("/var/log/auth.log") {
		if failedLogins := system.RunCommandWithTimeout("grep",
			[]string{"Failed password", "/var/log/auth.log", "|", "tail", "-20"}, 5*time.Second); failedLogins != "" {
			output.WriteString("\n=== Recent Failed Logins ===\n")
			output.WriteString(failedLogins)
			output.WriteString("\n")
		}
	}

	// Network connections
	output.WriteString("\n=== Network Connections ===\n")
	if netstatOutput := system.RunCommandWithTimeout("ss", []string{"-tuln"}, 5*time.Second); netstatOutput != "" {
		output.WriteString(netstatOutput)
	} else if netstatOutput := system.RunCommandWithTimeout("netstat", []string{"-tuln"}, 5*time.Second); netstatOutput != "" {
		output.WriteString(netstatOutput)
	}

	// Firewall status
	output.WriteString("\n\n=== Firewall Status ===\n")
	if ufwStatus := system.RunCommandWithTimeout("ufw", []string{"status", "verbose"}, 5*time.Second); ufwStatus != "" {
		output.WriteString("UFW:\n")
		output.WriteString(ufwStatus)
		output.WriteString("\n")
	}

	if iptablesOutput := system.RunCommandWithTimeout("iptables", []string{"-L", "-n"}, 5*time.Second); iptablesOutput != "" {
		output.WriteString("\nIPTables:\n")
		output.WriteString(iptablesOutput)
		output.WriteString("\n")
	}

	// SELinux/AppArmor status
	if selinuxStatus := system.RunCommandWithTimeout("getenforce", []string{}, 5*time.Second); selinuxStatus != "" {
		output.WriteString("\n=== SELinux Status ===\n")
		output.WriteString(selinuxStatus)
		output.WriteString("\n")
	}

	if apparmorStatus := system.RunCommandWithTimeout("aa-status", []string{}, 5*time.Second); apparmorStatus != "" {
		output.WriteString("\n=== AppArmor Status ===\n")
		// Limit output to first 50 lines
		lines := strings.Split(apparmorStatus, "\n")
		if len(lines) > 50 {
			output.WriteString(strings.Join(lines[:50], "\n"))
			output.WriteString("\n... (truncated)\n")
		} else {
			output.WriteString(apparmorStatus)
		}
		output.WriteString("\n")
	}

	// Running processes with security context
	output.WriteString("\n=== Suspicious Processes ===\n")
	if psOutput := system.RunCommandWithTimeout("ps",
		[]string{"aux", "--sort=-pcpu"}, 5*time.Second); psOutput != "" {
		lines := strings.Split(psOutput, "\n")
		for i, line := range lines {
			if i == 0 || i > 20 {
				if i == 0 {
					output.WriteString(line + "\n")
				}
				continue
			}
			// Look for suspicious patterns
			lowerLine := strings.ToLower(line)
			if strings.Contains(lowerLine, "nc ") ||
				strings.Contains(lowerLine, "ncat") ||
				strings.Contains(lowerLine, "cryptominer") ||
				strings.Contains(lowerLine, "xmrig") ||
				strings.Contains(lowerLine, "/tmp/") ||
				strings.Contains(lowerLine, "wget ") ||
				strings.Contains(lowerLine, "curl ") {
				output.WriteString(" " + line + "\n")
			}
		}
	}

	// EVALUATE - Write results
	if err := os.WriteFile(outputFile, []byte(output.String()), 0600); err != nil {
		return fmt.Errorf("failed to write security snapshot: %w", err)
	}

	logger.Info("Security snapshot completed",
		zap.String("output_file", outputFile))

	return nil
}
