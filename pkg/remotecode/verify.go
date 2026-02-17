// pkg/remotecode/verify.go
// Verification logic for remote IDE development setup

package remotecode

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerificationResult contains the results of verification checks
type VerificationResult struct {
	Checks    []VerificationCheck
	AllPassed bool
}

// VerificationCheck represents a single verification check
type VerificationCheck struct {
	Name    string
	Status  string // "pass", "fail", "warn"
	Message string
	Details string
}

// Verify checks that remote IDE configuration is correct and working
func Verify(rc *eos_io.RuntimeContext, config *Config) (*VerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying remote IDE development configuration")

	result := &VerificationResult{
		Checks:    []VerificationCheck{},
		AllPassed: true,
	}

	// Check architecture (P0 - Windsurf only supports x64)
	result.Checks = append(result.Checks, checkArchitecture(rc))

	// Check Windsurf connectivity (unless skipped)
	if !config.SkipConnectivityCheck {
		result.Checks = append(result.Checks, checkWindsurfConnectivityVerify(rc))
	}

	// Check disk space for IDE servers
	result.Checks = append(result.Checks, checkDiskSpace(rc, config.User))

	// Check SSH service status
	result.Checks = append(result.Checks, checkSSHService(rc))

	// Check SSH configuration values
	result.Checks = append(result.Checks, checkSSHSettings(rc, config))

	// Check SSH port is listening
	result.Checks = append(result.Checks, checkSSHPort(rc))

	// Check firewall rules
	if !config.SkipFirewall {
		result.Checks = append(result.Checks, checkFirewallRules(rc))
	}

	// Check for running IDE servers (informational)
	result.Checks = append(result.Checks, checkIDEServers(rc, config.User))

	// Determine overall status
	for _, check := range result.Checks {
		if check.Status == "fail" {
			result.AllPassed = false
		}
	}

	logger.Info("Verification completed",
		zap.Bool("all_passed", result.AllPassed),
		zap.Int("total_checks", len(result.Checks)))

	return result, nil
}

// checkArchitecture verifies the server is running x64 architecture
func checkArchitecture(rc *eos_io.RuntimeContext) VerificationCheck {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking architecture")

	arch := runtime.GOARCH
	if arch == "amd64" {
		return VerificationCheck{
			Name:    "Architecture",
			Status:  "pass",
			Message: "Server is running x64 (amd64) architecture",
			Details: fmt.Sprintf("GOARCH: %s", arch),
		}
	}

	return VerificationCheck{
		Name:    "Architecture",
		Status:  "fail",
		Message: fmt.Sprintf("Windsurf requires x64 architecture, but server is %s", arch),
		Details: "Alternative: Use VS Code Remote SSH or JetBrains Gateway which support ARM64",
	}
}

// checkWindsurfConnectivityVerify checks if server can reach Windsurf download domain
func checkWindsurfConnectivityVerify(rc *eos_io.RuntimeContext) VerificationCheck {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Windsurf connectivity")

	url := fmt.Sprintf("https://%s", WindsurfREHDomain)

	ctx, cancel := context.WithTimeout(rc.Ctx, ConnectivityCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return VerificationCheck{
			Name:    "Windsurf Connectivity",
			Status:  "fail",
			Message: "Failed to create connectivity check request",
			Details: err.Error(),
		}
	}

	client := &http.Client{Timeout: ConnectivityCheckTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return VerificationCheck{
			Name:    "Windsurf Connectivity",
			Status:  "fail",
			Message: fmt.Sprintf("Cannot reach %s", WindsurfREHDomain),
			Details: fmt.Sprintf("Error: %v\nRemediation: Check firewall/proxy settings", err),
		}
	}
	defer resp.Body.Close()

	return VerificationCheck{
		Name:    "Windsurf Connectivity",
		Status:  "pass",
		Message: fmt.Sprintf("Can reach %s", WindsurfREHDomain),
		Details: fmt.Sprintf("HTTP status: %d", resp.StatusCode),
	}
}

// checkDiskSpace verifies sufficient disk space for IDE servers
func checkDiskSpace(rc *eos_io.RuntimeContext, username string) VerificationCheck {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking disk space")

	// Determine home directory
	homeDir := "/root"
	if username != "" && username != "root" {
		homeDir = filepath.Join("/home", username)
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(homeDir, &stat); err != nil {
		return VerificationCheck{
			Name:    "Disk Space",
			Status:  "warn",
			Message: "Could not check disk space",
			Details: err.Error(),
		}
	}

	// Calculate free space in MB
	freeSpaceMB := (stat.Bavail * uint64(stat.Bsize)) / (1024 * 1024)

	if freeSpaceMB < MinDiskSpaceMB {
		return VerificationCheck{
			Name:    "Disk Space",
			Status:  "warn",
			Message: fmt.Sprintf("Low disk space: %d MB free (recommended: %d MB)", freeSpaceMB, MinDiskSpaceMB),
			Details: fmt.Sprintf("Path: %s\nWindsurf-reh is ~500MB plus extensions and cache", homeDir),
		}
	}

	return VerificationCheck{
		Name:    "Disk Space",
		Status:  "pass",
		Message: fmt.Sprintf("Sufficient disk space: %d MB free", freeSpaceMB),
		Details: fmt.Sprintf("Path: %s, Minimum recommended: %d MB", homeDir, MinDiskSpaceMB),
	}
}

// checkSSHService verifies SSH daemon is running
func checkSSHService(rc *eos_io.RuntimeContext) VerificationCheck {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking SSH service status")

	// Try sshd first, then ssh
	for _, serviceName := range []string{"sshd", "ssh"} {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", serviceName},
			Capture: true,
			Timeout: 5 * time.Second,
		})

		if err == nil && strings.TrimSpace(output) == "active" {
			return VerificationCheck{
				Name:    "SSH Service",
				Status:  "pass",
				Message: fmt.Sprintf("SSH service (%s) is running", serviceName),
				Details: output,
			}
		}
	}

	return VerificationCheck{
		Name:    "SSH Service",
		Status:  "fail",
		Message: "SSH service is not running",
		Details: "Start with: sudo systemctl start sshd",
	}
}

// checkSSHSettings verifies SSH configuration values
func checkSSHSettings(rc *eos_io.RuntimeContext, config *Config) VerificationCheck {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking SSH configuration settings")

	// Get effective SSH configuration
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sshd",
		Args:    []string{"-T"},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		return VerificationCheck{
			Name:    "SSH Settings",
			Status:  "fail",
			Message: "Failed to get SSH configuration",
			Details: err.Error(),
		}
	}

	// Parse settings
	settings := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(parts) == 2 {
			settings[strings.ToLower(parts[0])] = parts[1]
		}
	}

	var issues []string

	// Check MaxSessions
	if val, ok := settings["maxsessions"]; ok {
		if maxSessions, err := strconv.Atoi(val); err == nil {
			if maxSessions < config.MaxSessions {
				issues = append(issues, fmt.Sprintf("MaxSessions is %d, expected >= %d", maxSessions, config.MaxSessions))
			}
		}
	}

	// Check ClientAliveInterval
	if val, ok := settings["clientaliveinterval"]; ok {
		if cai, err := strconv.Atoi(val); err == nil {
			if cai == 0 {
				issues = append(issues, "ClientAliveInterval is disabled (0)")
			}
		}
	}

	// Check TCP forwarding
	if val, ok := settings["allowtcpforwarding"]; ok {
		if val != "yes" && val != "all" {
			issues = append(issues, fmt.Sprintf("AllowTcpForwarding is '%s', should be 'yes'", val))
		}
	}

	if len(issues) > 0 {
		return VerificationCheck{
			Name:    "SSH Settings",
			Status:  "warn",
			Message: "Some SSH settings may not be optimal",
			Details: strings.Join(issues, "\n"),
		}
	}

	return VerificationCheck{
		Name:    "SSH Settings",
		Status:  "pass",
		Message: "SSH settings are configured for remote IDE development",
		Details: fmt.Sprintf("MaxSessions=%s, ClientAliveInterval=%s",
			settings["maxsessions"], settings["clientaliveinterval"]),
	}
}

// checkSSHPort verifies SSH is listening on port 22
func checkSSHPort(rc *eos_io.RuntimeContext) VerificationCheck {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking SSH port")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp", fmt.Sprintf("sport = :%d", shared.PortSSH)},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil {
		return VerificationCheck{
			Name:    "SSH Port",
			Status:  "fail",
			Message: "Failed to check SSH port",
			Details: err.Error(),
		}
	}

	if strings.Contains(output, fmt.Sprintf(":%d", shared.PortSSH)) {
		return VerificationCheck{
			Name:    "SSH Port",
			Status:  "pass",
			Message: fmt.Sprintf("SSH is listening on port %d", shared.PortSSH),
			Details: strings.TrimSpace(output),
		}
	}

	return VerificationCheck{
		Name:    "SSH Port",
		Status:  "fail",
		Message: fmt.Sprintf("SSH is not listening on port %d", shared.PortSSH),
		Details: "Check SSH configuration and restart the service",
	}
}

// checkFirewallRules verifies firewall allows SSH
func checkFirewallRules(rc *eos_io.RuntimeContext) VerificationCheck {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking firewall rules")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ufw",
		Args:    []string{"status"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil {
		return VerificationCheck{
			Name:    "Firewall Rules",
			Status:  "warn",
			Message: "Could not check firewall status",
			Details: "UFW may not be installed: " + err.Error(),
		}
	}

	// Check if inactive
	if strings.Contains(output, "Status: inactive") {
		return VerificationCheck{
			Name:    "Firewall Rules",
			Status:  "warn",
			Message: "Firewall is inactive",
			Details: "SSH is accessible but no firewall protection is active",
		}
	}

	// Check for SSH rules
	if strings.Contains(output, "22") || strings.Contains(strings.ToLower(output), "ssh") {
		return VerificationCheck{
			Name:    "Firewall Rules",
			Status:  "pass",
			Message: "Firewall allows SSH access",
			Details: filterSSHRules(output),
		}
	}

	return VerificationCheck{
		Name:    "Firewall Rules",
		Status:  "warn",
		Message: "No explicit SSH rules found in firewall",
		Details: "SSH may still be accessible if default policy allows",
	}
}

// checkIDEServers checks for running IDE server processes
func checkIDEServers(rc *eos_io.RuntimeContext, username string) VerificationCheck {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking for running IDE servers")

	// Look for common IDE server processes
	patterns := []string{
		"windsurf-server",
		"vscode-server",
		"code-server",
		"cursor-server",
	}

	var running []string
	for _, pattern := range patterns {
		cmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", pattern)
		if output, err := cmd.Output(); err == nil && len(output) > 0 {
			count := len(strings.Split(strings.TrimSpace(string(output)), "\n"))
			running = append(running, fmt.Sprintf("%s (%d processes)", pattern, count))
		}
	}

	if len(running) > 0 {
		return VerificationCheck{
			Name:    "IDE Servers",
			Status:  "pass",
			Message: "IDE server processes detected",
			Details: strings.Join(running, ", "),
		}
	}

	return VerificationCheck{
		Name:    "IDE Servers",
		Status:  "pass",
		Message: "No IDE servers currently running",
		Details: "IDE servers will start when you connect from your IDE",
	}
}

// filterSSHRules extracts SSH-related rules from UFW output
func filterSSHRules(output string) string {
	var sshRules []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "22") || strings.Contains(strings.ToLower(trimmed), "ssh") {
			sshRules = append(sshRules, trimmed)
		}
	}

	if len(sshRules) == 0 {
		return "No SSH-specific rules found"
	}

	return strings.Join(sshRules, "\n")
}

// FormatVerificationResult formats the verification result for display
func FormatVerificationResult(result *VerificationResult) string {
	var sb strings.Builder

	sb.WriteString("\nConfiguration Verification\n")
	sb.WriteString(strings.Repeat("=", 40) + "\n\n")

	for _, check := range result.Checks {
		var icon string
		switch check.Status {
		case "pass":
			icon = "✓"
		case "fail":
			icon = "✗"
		case "warn":
			icon = "⚠"
		default:
			icon = "?"
		}

		sb.WriteString(fmt.Sprintf("%s %s: %s\n", icon, check.Name, check.Message))
		if check.Details != "" {
			// Indent details
			for _, line := range strings.Split(check.Details, "\n") {
				if line != "" {
					sb.WriteString(fmt.Sprintf("    %s\n", line))
				}
			}
		}
		sb.WriteString("\n")
	}

	if result.AllPassed {
		sb.WriteString("All checks passed! System is ready for remote IDE development.\n")
	} else {
		sb.WriteString("Some checks failed. Please review the issues above.\n")
	}

	return sb.String()
}
