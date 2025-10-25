package debug

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// checkPortConflicts checks if Consul ports are already in use
func checkPortConflicts(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking for port conflicts")

	result := DiagnosticResult{
		CheckName: "Port Conflicts",
		Success:   true,
		Details:   []string{},
	}

	// Check HTTP port and DNS port
	ports := map[string]int{
		"HTTP": shared.PortConsul, // 8161 from shared/ports.go
		"DNS":  8600,              // Standard Consul DNS port
	}

	for name, port := range ports {
		// Use ss command to check port usage
		cmd := execute.Options{
			Command: "ss",
			Args:    []string{"-tlnp"},
			Capture: true,
		}

		output, err := execute.Run(rc.Ctx, cmd)
		if err != nil {
			// Fallback to netstat if ss fails
			cmd = execute.Options{
				Command: "netstat",
				Args:    []string{"-tlnp"},
				Capture: true,
			}
			output, _ = execute.Run(rc.Ctx, cmd)
		}

		portStr := fmt.Sprintf(":%d", port)
		if strings.Contains(output, portStr) {
			// Port is in use - check WHO owns it
			// ss/netstat output format: users:(("consul",pid=274995,fd=22))
			isConsulOwned := strings.Contains(output, `"consul"`) || strings.Contains(output, "consul,pid=")

			if isConsulOwned {
				// Consul owns its own ports - this is GOOD
				result.Details = append(result.Details,
					fmt.Sprintf("✓ Port %d (%s): Correctly bound by Consul", port, name))
			} else {
				// Another process owns the port - this is a CONFLICT
				result.Success = false
				result.Severity = SeverityWarning // WARNING: Port conflict may prevent startup
				result.Details = append(result.Details,
					fmt.Sprintf("✗ Port %d (%s): In use by conflicting process", port, name))

				// Show which process owns it
				lines := strings.Split(output, "\n")
				for _, line := range lines {
					if strings.Contains(line, portStr) {
						result.Details = append(result.Details, "  Conflict: "+strings.TrimSpace(line))
					}
				}
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("✓ Port %d (%s): Available (not in use)", port, name))
		}
	}

	if result.Success {
		result.Message = "All Consul ports are available or correctly bound"
	} else {
		result.Message = "One or more Consul ports have conflicts"
	}

	return result
}

// checkLingeringProcesses checks for consul processes that might be running
func checkLingeringProcesses(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking for lingering Consul processes")

	result := DiagnosticResult{
		CheckName: "Lingering Processes",
		Success:   true,
		Details:   []string{},
	}

	// Use pgrep for accurate process matching (matches command name, not username)
	cmd := execute.Options{
		Command: "pgrep",
		Args:    []string{"-a", "consul"}, // -a shows full command line
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		// pgrep returns exit code 1 when no processes found - this is normal
		if strings.TrimSpace(output) == "" {
			result.Message = "No lingering Consul processes found"
			return result
		}
		// Other errors
		result.Message = "Could not check for processes"
		return result
	}

	// Parse pgrep output: "PID COMMAND LINE"
	// Example: "274995 /usr/bin/consul agent -config-dir=/etc/consul.d/"
	lines := strings.Split(output, "\n")
	consulProcesses := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Filter out processes that are this debug command itself
		if strings.Contains(line, "eos debug consul") || strings.Contains(line, "eos update consul") {
			continue
		}

		consulProcesses = append(consulProcesses, line)
	}

	if len(consulProcesses) > 0 {
		result.Success = false
		result.Severity = SeverityWarning // WARNING: Should clean up but doesn't block startup
		result.Message = fmt.Sprintf("Found %d lingering Consul process(es)", len(consulProcesses))
		result.Details = consulProcesses
	} else {
		result.Message = "No lingering Consul processes found"
	}

	return result
}

// checkConsulBinary verifies the Consul binary exists and has correct permissions
func checkConsulBinary(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Consul binary")

	result := DiagnosticResult{
		CheckName: "Consul Binary",
		Success:   true,
		Details:   []string{},
	}

	// Use centralized binary path lookup (checks both /usr/local/bin and /usr/bin)
	binPath := consul.GetConsulBinaryPath()

	// Check if binary exists at detected path
	info, err := os.Stat(binPath)
	if err != nil {
		result.Success = false
		result.Severity = SeverityCritical // CRITICAL: Can't start without binary
		result.Message = "Consul binary not found"
		result.Details = append(result.Details, fmt.Sprintf("Searched: %s and %s",
			consul.ConsulBinaryPath, consul.ConsulBinaryPathAlt))
		result.Details = append(result.Details, "Install with: eos create consul")
		return result
	}

	// Check permissions
	mode := info.Mode()
	if mode&0111 == 0 {
		result.Success = false
		result.Severity = SeverityCritical // CRITICAL: Binary exists but can't execute
		result.Message = "Consul binary is not executable"
		result.Details = append(result.Details,
			fmt.Sprintf("Current permissions: %s", mode))
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("Binary found at %s", binPath))
		result.Details = append(result.Details,
			fmt.Sprintf("Permissions: %s", mode))

		// Try to get version
		cmd := execute.Options{
			Command: binPath,
			Args:    []string{"version"},
			Capture: true,
		}

		output, err := execute.Run(rc.Ctx, cmd)
		if err == nil {
			versionLine := strings.Split(output, "\n")[0]
			result.Details = append(result.Details,
				fmt.Sprintf("Version: %s", versionLine))
		}

		result.Message = "Consul binary is valid"
	}

	return result
}

// checkConsulPermissions verifies file permissions for Consul directories and files
// Uses centralized path checks from pkg/consul/constants.go (single source of truth)
func checkConsulPermissions(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Consul file permissions")

	result := DiagnosticResult{
		CheckName: "File Permissions",
		Success:   true,
		Details:   []string{},
	}

	// Get consul user for ownership verification
	consulUser, err := user.Lookup("consul")
	var expectedUID, expectedGID int
	if err != nil {
		result.Success = false
		result.Severity = SeverityCritical // CRITICAL: No consul user = can't run consul service
		result.Message = "consul user does not exist"
		result.Details = append(result.Details, "✗ consul system user not found - run 'eos create consul' first")
		return result
	}
	expectedUID, _ = strconv.Atoi(consulUser.Uid)
	expectedGID, _ = strconv.Atoi(consulUser.Gid)

	// Get centralized path checks (single source of truth)
	pathsToCheck := consul.GetAllPathChecks()

	issuesFound := 0
	criticalIssues := 0
	for _, check := range pathsToCheck {
		info, err := os.Stat(check.Path)
		if err != nil {
			if check.Critical {
				result.Success = false
				result.Details = append(result.Details,
					fmt.Sprintf("✗ %s (%s): MISSING (CRITICAL)", check.Description, check.Path))
				issuesFound++
				criticalIssues++
			} else {
				result.Details = append(result.Details,
					fmt.Sprintf("⊘ %s (%s): Does not exist (optional)", check.Description, check.Path))
			}
			continue
		}

		// Get file ownership
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			result.Details = append(result.Details,
				fmt.Sprintf("⚠ %s (%s): Cannot read ownership info", check.Description, check.Path))
			continue
		}

		// Determine expected UID/GID based on expected user
		var checkUID, checkGID int
		if check.ExpectedUser == "root" {
			checkUID = 0
			checkGID = 0
		} else {
			checkUID = expectedUID
			checkGID = expectedGID
		}

		// Verify ownership
		ownershipOK := stat.Uid == uint32(checkUID) && stat.Gid == uint32(checkGID)

		// Verify permissions
		actualPerm := info.Mode().Perm()
		permissionsOK := actualPerm == check.ExpectedPerm

		// Report results
		if ownershipOK && permissionsOK {
			result.Details = append(result.Details,
				fmt.Sprintf("✓ %s (%s): %s %s:%s OK",
					check.Description, check.Path, actualPerm,
					check.ExpectedUser, check.ExpectedGroup))
		} else {
			if check.Critical {
				result.Success = false
				criticalIssues++
			}

			details := fmt.Sprintf("✗ %s (%s):", check.Description, check.Path)
			if !ownershipOK {
				details += fmt.Sprintf(" owner=%d:%d (expected %s:%s=%d:%d)",
					stat.Uid, stat.Gid,
					check.ExpectedUser, check.ExpectedGroup,
					checkUID, checkGID)
			}
			if !permissionsOK {
				details += fmt.Sprintf(" mode=%04o (expected %04o)",
					actualPerm, check.ExpectedPerm)
			}
			if check.Critical {
				details += " [CRITICAL]"
			}

			result.Details = append(result.Details, details)
			issuesFound++
		}
	}

	// Set severity based on whether critical files are affected
	if criticalIssues > 0 {
		result.Severity = SeverityCritical // Critical config files unreadable/missing
	} else if issuesFound > 0 {
		result.Severity = SeverityWarning // Only non-critical permission issues
	}

	// Summary message
	if issuesFound > 0 {
		result.Message = fmt.Sprintf("Found %d permission/ownership issue(s)", issuesFound)
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Fix with: sudo eos update consul --fix")
	} else {
		result.Message = "All permissions and ownership are correct"
	}

	return result
}

// checkSystemdService verifies the systemd service configuration
func checkSystemdService(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking systemd service configuration")

	result := DiagnosticResult{
		CheckName: "Systemd Service",
		Success:   true,
		Details:   []string{},
	}

	servicePath := "/etc/systemd/system/consul.service"

	// Check if service file exists
	if _, err := os.Stat(servicePath); err != nil {
		result.Success = false
		result.Severity = SeverityWarning // WARNING: Service file missing, should regenerate
		result.Message = "Systemd service file not found"
		result.Details = append(result.Details,
			fmt.Sprintf("Expected path: %s", servicePath))
		return result
	}

	result.Details = append(result.Details,
		fmt.Sprintf("Service file exists: %s", servicePath))

	// Check service status
	cmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "consul.service", "--no-pager"},
		Capture: true,
	}

	output, _ := execute.Run(rc.Ctx, cmd)

	// Parse output for key information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Active:") ||
			strings.Contains(line, "Loaded:") ||
			strings.Contains(line, "Main PID:") {
			result.Details = append(result.Details, strings.TrimSpace(line))
		}
	}

	// Check if enabled
	enabledCmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"is-enabled", "consul.service"},
		Capture: true,
	}

	enabledOutput, _ := execute.Run(rc.Ctx, enabledCmd)
	result.Details = append(result.Details,
		fmt.Sprintf("Enabled: %s", strings.TrimSpace(enabledOutput)))

	result.Message = "Systemd service configuration is valid"

	return result
}

// analyzeLogs retrieves and analyzes recent Consul logs
func analyzeLogs(rc *eos_io.RuntimeContext, lines int) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Analyzing Consul logs", zap.Int("lines", lines))

	result := DiagnosticResult{
		CheckName: "Log Analysis",
		Success:   true,
		Details:   []string{},
	}

	// Get recent logs
	cmd := execute.Options{
		Command: "journalctl",
		Args:    []string{"-u", "consul.service", "--no-pager", "-n", strconv.Itoa(lines), "--since", "1 hour ago"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Message = "No recent logs found"
		return result
	}

	// Analyze logs for common error patterns
	errorPatterns := map[string]string{
		"bind: address already in use": "Port binding conflict detected",
		"permission denied":            "Permission issues detected",
		"no such file or directory":    "Missing files or directories",
		"signal: killed":               "Process was killed (likely timeout)",
		"failed to join":               "Cluster join issues",
		"error getting server health":  "Health check failures",
	}

	foundIssues := []string{}
	logLines := strings.Split(output, "\n")

	for pattern, description := range errorPatterns {
		for _, line := range logLines {
			if strings.Contains(strings.ToLower(line), pattern) {
				foundIssues = append(foundIssues, description)
				result.Details = append(result.Details, "Found: "+line)
				break
			}
		}
	}

	if len(foundIssues) > 0 {
		result.Success = false
		result.Severity = SeverityInfo // INFO: Log issues are informational, not blocking
		result.Message = fmt.Sprintf("Found %d issue(s) in logs", len(foundIssues))

		// Preserve actual log lines captured above
		logDetails := result.Details

		// Build summary with both descriptions AND actual log lines
		result.Details = []string{"Issues detected:"}
		result.Details = append(result.Details, foundIssues...)
		result.Details = append(result.Details, "") // Blank line for readability
		result.Details = append(result.Details, logDetails...)
	} else {
		result.Message = "No critical issues found in recent logs"
		result.Details = append(result.Details, "Recent logs look clean")
	}

	return result
}

// analyzeConfiguration analyzes the Consul configuration file
func analyzeConfiguration(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Analyzing Consul configuration")

	result := DiagnosticResult{
		CheckName: "Configuration Analysis",
		Success:   true,
		Details:   []string{},
	}

	configPath := consul.ConsulConfigFile

	// Check if config file exists
	if _, err := os.Stat(configPath); err != nil {
		result.Success = false
		result.Severity = SeverityCritical // CRITICAL: No config = can't start
		result.Message = "Consul configuration file not found"
		result.Details = append(result.Details, configPath+" does not exist")
		return result
	}

	// Read configuration
	content, err := os.ReadFile(configPath)
	if err != nil {
		result.Success = false
		result.Message = "Failed to read configuration file"
		return result
	}

	configStr := string(content)

	// Extract key configuration values
	bindAddr := extractConfigValue(configStr, "bind_addr")
	advertiseAddr := extractConfigValue(configStr, "advertise_addr")
	clientAddr := extractConfigValue(configStr, "client_addr")
	retryJoin := extractConfigArray(configStr, "retry_join")

	// Report extracted configuration
	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "=== Configuration Values ===")
	if bindAddr != "" {
		result.Details = append(result.Details, fmt.Sprintf("bind_addr = %s", bindAddr))
	} else {
		result.Details = append(result.Details, "bind_addr = (not set - will use default interface)")
	}

	if advertiseAddr != "" {
		result.Details = append(result.Details, fmt.Sprintf("advertise_addr = %s", advertiseAddr))
	}

	if clientAddr != "" {
		result.Details = append(result.Details, fmt.Sprintf("client_addr = %s", clientAddr))
	} else {
		result.Details = append(result.Details, "client_addr = (not set - will use 127.0.0.1)")
	}

	if len(retryJoin) > 0 {
		result.Details = append(result.Details, fmt.Sprintf("retry_join = [%s]", strings.Join(retryJoin, ", ")))
	} else {
		result.Details = append(result.Details, "retry_join = (not set - single node or manual join)")
	}
	result.Details = append(result.Details, "")

	// Check for common configuration issues
	issues := []string{}

	// Bootstrap configuration check
	if strings.Contains(configStr, "bootstrap = true") && strings.Contains(configStr, "bootstrap_expect") {
		issues = append(issues, "Both 'bootstrap' and 'bootstrap_expect' are set - use only one")
		result.Details = append(result.Details, "Fix: Remove 'bootstrap_expect' for single-node setup")
	}

	// Script checks warning
	if strings.Contains(configStr, "enable_script_checks = true") {
		issues = append(issues, "Using 'enable_script_checks' without ACLs is dangerous")
		result.Details = append(result.Details, "Fix: Change to 'enable_local_script_checks = true'")
	}

	// Bind address check
	if !strings.Contains(configStr, "bind_addr") && !strings.Contains(configStr, "client_addr") {
		issues = append(issues, "No bind addresses specified")
		result.Details = append(result.Details, "Consider adding: bind_addr = \"0.0.0.0\"")
	}

	// Data directory check
	if !strings.Contains(configStr, "data_dir") {
		issues = append(issues, "No data directory specified")
		result.Details = append(result.Details, "Fix: Add 'data_dir = \"/opt/consul\"'")
	}

	if len(issues) > 0 {
		result.Success = false
		result.Severity = SeverityCritical // CRITICAL: Invalid config prevents startup
		result.Message = fmt.Sprintf("Found %d configuration issue(s)", len(issues))
		for _, issue := range issues {
			result.Details = append(result.Details, "• "+issue)
		}
	} else {
		result.Message = "Configuration appears valid"

		// Validation strategy:
		// 1. Try SDK validation (if Consul is running)
		// 2. Fallback to CLI validation (if binary exists)
		validated := false

		// Try SDK validation first
		client, err := consulapi.NewClient(consulapi.DefaultConfig())
		if err == nil {
			if _, err := client.Agent().Self(); err == nil {
				result.Details = append(result.Details, "✓ SDK validation: Consul agent responding")
				validated = true
			} else {
				logger.Debug("SDK validation failed - Consul may not be running",
					zap.Error(err))
			}
		}

		// Fallback to CLI validation if SDK failed
		if !validated {
			binPath := consul.GetConsulBinaryPath()
			if _, err := os.Stat(binPath); err == nil {
				validateCmd := execute.Options{
					Command: binPath,
					Args:    []string{"validate", consul.ConsulConfigDir},
					Capture: true,
				}

				output, err := execute.Run(rc.Ctx, validateCmd)
				if err != nil {
					result.Success = false
					result.Details = append(result.Details, fmt.Sprintf("✗ CLI validation failed: %s", output))
					result.Details = append(result.Details, fmt.Sprintf("   Command: %s validate %s", binPath, consul.ConsulConfigDir))
				} else {
					result.Details = append(result.Details, "✓ CLI validation passed")
					_ = validated // Mark as validated
					validated = true
				}
			} else {
				result.Details = append(result.Details, "⚠ Cannot validate: Consul binary not found and agent not running")
				logger.Warn("Cannot validate configuration - binary not found",
					zap.String("searched_paths", fmt.Sprintf("%s, %s", consul.ConsulBinaryPath, consul.ConsulBinaryPathAlt)))
			}
		}
	}

	return result
}

// checkConsulNetwork checks network configuration
func checkConsulNetwork(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking network configuration")

	result := DiagnosticResult{
		CheckName: "Network Configuration",
		Success:   true,
		Details:   []string{},
	}

	// Get network interfaces
	cmd := execute.Options{
		Command: "ip",
		Args:    []string{"addr", "show"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Message = "Could not retrieve network information"
		return result
	}

	// Parse output for IP addresses
	lines := strings.Split(output, "\n")
	ipAddresses := []string{}

	for _, line := range lines {
		if strings.Contains(line, "inet ") && !strings.Contains(line, "inet6") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ipAddresses = append(ipAddresses, fields[1])
			}
		}
	}

	result.Details = append(result.Details, "Network interfaces:")
	for _, ip := range ipAddresses {
		result.Details = append(result.Details, "  "+ip)
	}

	if len(ipAddresses) > 1 {
		result.Details = append(result.Details,
			"\nNote: Multiple network interfaces detected")
		result.Details = append(result.Details,
			"Ensure Consul bind_addr is set correctly in configuration")
	}

	result.Message = fmt.Sprintf("Found %d network interface(s)", len(ipAddresses))
	return result
}

// checkConsulPorts checks if Consul ports are accessible
func checkConsulPorts(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Consul port connectivity")

	result := DiagnosticResult{
		CheckName: "Port Connectivity",
		Success:   true,
		Details:   []string{},
	}

	ports := map[int]string{
		shared.PortConsul: "HTTP API",
		8502:              "gRPC",
		8600:              "DNS",
		8301:              "Serf LAN",
		8302:              "Serf WAN",
		8300:              "RPC",
	}

	httpWorking := false
	for port, desc := range ports {
		// Use net.JoinHostPort for IPv6 compatibility (handles [::1]:port syntax)
		addr := net.JoinHostPort(shared.GetInternalHostname(), strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			result.Details = append(result.Details,
				fmt.Sprintf("✓ Port %d (%s): LISTENING", port, desc))
			if port == shared.PortConsul {
				httpWorking = true
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("✗ Port %d (%s): NOT LISTENING", port, desc))
		}
	}

	// Try HTTP request to Consul API
	if httpWorking {
		client := &http.Client{Timeout: 5 * time.Second}
		// Build URL with net.JoinHostPort for IPv6 compatibility
		hostPort := net.JoinHostPort(shared.GetInternalHostname(), strconv.Itoa(shared.PortConsul))
		apiURL := fmt.Sprintf("http://%s/v1/agent/self", hostPort)
		resp, err := client.Get(apiURL)
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			result.Details = append(result.Details,
				fmt.Sprintf("\nHTTP API Response: %s", resp.Status))
			result.Message = "Consul API is responding"
		} else {
			result.Success = false
			result.Message = "Consul ports listening but API not responding"
			result.Details = append(result.Details,
				fmt.Sprintf("\nHTTP API Error: %v", err))
		}
	} else {
		result.Success = false
		result.Severity = SeverityInfo // INFO: Port not listening is expected if Consul not running
		result.Message = "Consul HTTP API port not listening"
	}

	return result
}

// checkVaultConsulConnectivity checks if Vault can reach Consul (critical for Vault storage backend)
// Uses HashiCorp SDKs for granular error detection and structured data access
func checkVaultConsulConnectivity(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Vault-Consul connectivity using SDKs")

	result := DiagnosticResult{
		CheckName: "Vault-Consul Connectivity",
		Success:   true,
		Details:   []string{},
	}

	hostname := shared.GetInternalHostname()

	// STEP 1: Check /etc/hosts for hostname resolution (using Go stdlib, not shell)
	logger.Debug("Checking /etc/hosts for hostname resolution")
	hostsContent, err := os.ReadFile("/etc/hosts")
	if err != nil {
		result.Details = append(result.Details, fmt.Sprintf("⚠ Could not read /etc/hosts: %v", err))
		logger.Warn("Failed to read /etc/hosts", zap.Error(err))
	} else {
		result.Details = append(result.Details, fmt.Sprintf("Checking hostname resolution for: %s", hostname))

		// Parse /etc/hosts for the hostname
		hostsLines := strings.Split(string(hostsContent), "\n")
		foundHostname := false
		for _, line := range hostsLines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := fields[0]
				for _, host := range fields[1:] {
					if host == hostname {
						foundHostname = true
						result.Details = append(result.Details,
							fmt.Sprintf("  /etc/hosts: %s → %s", hostname, ip))

						// Check for suspicious 127.0.1.1 mapping (Ubuntu default)
						if ip == "127.0.1.1" {
							result.Details = append(result.Details,
								"  ⚠ WARNING: Hostname maps to 127.0.1.1 (Ubuntu default)")
							result.Details = append(result.Details,
								"    This causes issues when Vault uses hostname for Consul address")
							result.Details = append(result.Details,
								fmt.Sprintf("    Consul binds to: %s (Tailscale IP)", shared.GetInternalHostname()))
							result.Details = append(result.Details,
								"    But Vault resolves hostname to: 127.0.1.1")
						}
					}
				}
			}
		}
		if !foundHostname {
			result.Details = append(result.Details, fmt.Sprintf("  ⚠ %s not found in /etc/hosts", hostname))
		}
	}

	// STEP 2: Check Consul configuration using SDK (not ss/netstat)
	logger.Debug("Querying Consul agent configuration via SDK")
	result.Details = append(result.Details, "\nConsul agent configuration (via SDK):")

	// Try multiple addresses to find a working Consul connection
	// NOTE: Consul binds to actual network interface (Tailscale IP), not localhost
	// We test localhost as fallback only for troubleshooting misconfigurations
	testAddresses := []string{
		fmt.Sprintf("%s:%d", hostname, shared.PortConsul),                     // Primary: hostname (should resolve to Tailscale/actual IP)
		fmt.Sprintf("%s:%d", shared.GetInternalHostname(), shared.PortConsul), // Fallback: explicit internal hostname
		fmt.Sprintf("127.0.0.1:%d", shared.PortConsul),                        // Fallback: IPv4 localhost (diagnoses client_addr misconfiguration)
		fmt.Sprintf("127.0.1.1:%d", shared.PortConsul),                        // Fallback: Ubuntu default (diagnoses /etc/hosts issues)
	}

	var consulAgentInfo map[string]map[string]interface{}
	var consulConnectedAddr string

	for _, addr := range testAddresses {
		config := consulapi.DefaultConfig()
		config.Address = addr
		consulClient, err := consulapi.NewClient(config)
		if err != nil {
			logger.Debug("Failed to create Consul client", zap.String("address", addr), zap.Error(err))
			continue
		}

		agentInfo, err := consulClient.Agent().Self()
		if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("  ✗ %s: %v", addr, err))
			logger.Debug("Consul Agent().Self() failed", zap.String("address", addr), zap.Error(err))
			continue
		}

		// Success! We got structured data from Consul
		consulAgentInfo = agentInfo
		consulConnectedAddr = addr
		result.Details = append(result.Details, fmt.Sprintf("  ✓ Connected to Consul at: %s", addr))
		logger.Info("Successfully connected to Consul via SDK", zap.String("address", addr))
		break
	}

	// Extract structured configuration from Consul SDK response
	if consulAgentInfo != nil {
		if debugConfig, ok := consulAgentInfo["DebugConfig"]; ok {
			if bindAddr, ok := debugConfig["BindAddr"].(string); ok {
				result.Details = append(result.Details, fmt.Sprintf("  Consul BindAddr: %s", bindAddr))
			}
			if clientAddr, ok := debugConfig["ClientAddr"].(string); ok {
				result.Details = append(result.Details, fmt.Sprintf("  Consul ClientAddr: %s", clientAddr))
			}
			if advertiseAddr, ok := debugConfig["AdvertiseAddr"].(string); ok {
				result.Details = append(result.Details, fmt.Sprintf("  Consul AdvertiseAddr: %s", advertiseAddr))
			}
			if ports, ok := debugConfig["Ports"].(map[string]interface{}); ok {
				if httpPort, ok := ports["HTTP"].(float64); ok {
					result.Details = append(result.Details, fmt.Sprintf("  Consul HTTP Port: %.0f", httpPort))
				}
			}
		}
	} else {
		result.Success = false
		result.Details = append(result.Details, "  ✗ Could not connect to Consul on any address")
		result.Details = append(result.Details, "    Consul may not be running or accessible")
	}

	// STEP 3: Check Vault configuration for Consul address (using Go stdlib, not grep)
	logger.Debug("Reading Vault configuration file")
	vaultConfigPath := "/etc/vault.d/vault.hcl"
	vaultConsulAddr := ""

	if _, err := os.Stat(vaultConfigPath); err == nil {
		vaultConfigContent, err := os.ReadFile(vaultConfigPath)
		if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("\n⚠ Could not read Vault config: %v", err))
			logger.Warn("Failed to read Vault config", zap.Error(err))
		} else {
			result.Details = append(result.Details, "\nVault storage backend configuration:")
			configLines := strings.Split(string(vaultConfigContent), "\n")

			// Simple parsing for storage "consul" block
			inConsulBlock := false
			for _, line := range configLines {
				trimmed := strings.TrimSpace(line)

				if strings.Contains(trimmed, `storage "consul"`) {
					inConsulBlock = true
					result.Details = append(result.Details, "  Found: storage \"consul\" {")
					continue
				}

				if inConsulBlock {
					if trimmed == "}" {
						break
					}

					if strings.Contains(trimmed, "address") && strings.Contains(trimmed, "=") {
						result.Details = append(result.Details, fmt.Sprintf("    %s", trimmed))

						// Extract address value
						parts := strings.Split(trimmed, "=")
						if len(parts) == 2 {
							addr := strings.Trim(strings.TrimSpace(parts[1]), `"`)
							vaultConsulAddr = addr
							result.Details = append(result.Details,
								fmt.Sprintf("  → Vault will connect to Consul at: %s", addr))
						}
					}
				}
			}
		}
	} else {
		result.Details = append(result.Details, "\n⚠ Vault config not found at /etc/vault.d/vault.hcl")
		logger.Warn("Vault config file not found", zap.String("path", vaultConfigPath))
	}

	// STEP 4: Try Vault SDK health check to detect storage backend errors
	logger.Debug("Checking Vault health via SDK")
	result.Details = append(result.Details, "\nVault health check (via SDK):")

	vaultConfig := vaultapi.DefaultConfig()
	vaultConfig.Address = fmt.Sprintf("https://%s:8200", hostname)
	vaultClient, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		result.Details = append(result.Details, fmt.Sprintf("  ⚠ Could not create Vault client: %v", err))
		logger.Warn("Failed to create Vault client", zap.Error(err))
	} else {
		health, err := vaultClient.Sys().Health()
		if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("  ✗ Vault health check failed: %v", err))
			logger.Debug("Vault health check error", zap.Error(err))

			// Check if error is related to Consul storage backend
			if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "8500") {
				result.Success = false
				result.Details = append(result.Details, "  ⚠ Error suggests Vault cannot reach Consul storage backend!")
			}
		} else {
			result.Details = append(result.Details, fmt.Sprintf("  ✓ Vault responding (initialized: %v, sealed: %v)",
				health.Initialized, health.Sealed))
			logger.Info("Vault health check successful", zap.Bool("initialized", health.Initialized), zap.Bool("sealed", health.Sealed))

			if health.Sealed {
				result.Details = append(result.Details, "  Note: Vault is sealed (expected after restart)")
			}
		}
	}

	// STEP 5: Connectivity summary and diagnosis
	result.Details = append(result.Details, "\nConnectivity Summary:")
	if consulConnectedAddr != "" {
		result.Details = append(result.Details, fmt.Sprintf("  ✓ Consul reachable at: %s", consulConnectedAddr))
	} else {
		result.Success = false
		result.Details = append(result.Details, "  ✗ Consul NOT reachable on any tested address")
	}

	if vaultConsulAddr != "" {
		result.Details = append(result.Details, fmt.Sprintf("  Vault configured to use: %s", vaultConsulAddr))

		// Check for mismatch
		if consulConnectedAddr != "" && !strings.Contains(vaultConsulAddr, consulConnectedAddr) {
			result.Success = false
			result.Details = append(result.Details, "\n  ⚠ MISMATCH DETECTED:")
			result.Details = append(result.Details, fmt.Sprintf("    Vault expects: %s", vaultConsulAddr))
			result.Details = append(result.Details, fmt.Sprintf("    Consul reachable at: %s", consulConnectedAddr))
			result.Details = append(result.Details, "    This is likely why Vault cannot connect!")
		}
	}

	// EVALUATE
	if !result.Success {
		result.Message = "Consul connectivity issues detected - Vault storage backend may fail"
		result.Details = append(result.Details, "\nRemediation:")
		result.Details = append(result.Details, "  1. Ensure Consul is running: sudo systemctl start consul")
		result.Details = append(result.Details, "  2. Check Consul is listening on correct address")
		result.Details = append(result.Details, "  3. Verify Vault config matches Consul's actual address")
		result.Details = append(result.Details, "  4. Check /etc/hosts for hostname resolution issues")
	} else {
		result.Message = "Consul is reachable for Vault storage backend"
	}

	return result
}

// checkACLEnabled verifies ACLs are enabled in Consul configuration
// P0: ACLs are enabled by default in 'eos create consul' for security-by-default
// This check detects if ACLs were manually disabled (drift from canonical state)
func checkACLEnabled(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking ACL system status")

	result := DiagnosticResult{
		CheckName: "ACL System Status",
		Success:   true,
		Details:   []string{},
	}

	configPath := consul.ConsulConfigFile

	// ASSESS - Check if config file exists
	if _, err := os.Stat(configPath); err != nil {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Cannot check ACL status - configuration file not found"
		result.Details = append(result.Details, fmt.Sprintf("Config file missing: %s", configPath))
		return result
	}

	// ASSESS - Read configuration
	content, err := os.ReadFile(configPath)
	if err != nil {
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Failed to read configuration file for ACL check"
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		return result
	}

	configStr := string(content)

	// ASSESS - Check if ACL block exists and is enabled
	// Look for: acl { enabled = true } or acl = { enabled = true }
	hasACLBlock := strings.Contains(configStr, "acl") && (strings.Contains(configStr, "acl {") || strings.Contains(configStr, "acl ="))
	aclEnabled := strings.Contains(configStr, "enabled = true") && hasACLBlock

	if !hasACLBlock {
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "ACL block missing from configuration"
		result.Details = append(result.Details, "Consul is running WITHOUT access control lists")
		result.Details = append(result.Details, "This is NOT secure for production use")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Expected ACL block:")
		result.Details = append(result.Details, "  acl = {")
		result.Details = append(result.Details, "    enabled = true")
		result.Details = append(result.Details, "    default_policy = \"deny\"")
		result.Details = append(result.Details, "    enable_token_persistence = true")
		result.Details = append(result.Details, "  }")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Fix: eos update consul --enable-acls")
		return result
	}

	if !aclEnabled {
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "ACLs are DISABLED in configuration"
		result.Details = append(result.Details, "ACL block exists but enabled = false (or not set)")
		result.Details = append(result.Details, "Consul is running in OPEN MODE - anyone can do anything")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Security Impact:")
		result.Details = append(result.Details, "  • No authentication required for API operations")
		result.Details = append(result.Details, "  • No authorization checks")
		result.Details = append(result.Details, "  • Any client can read/write ANY data")
		result.Details = append(result.Details, "  • Service registration/deregistration unprotected")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Fix: eos update consul --enable-acls")
		return result
	}

	// SUCCESS - ACLs are enabled
	result.Message = "ACLs are enabled in configuration"
	result.Details = append(result.Details, "✓ ACL system is enabled")

	// Extract default_policy
	defaultPolicy := extractConfigValue(configStr, "default_policy")
	if defaultPolicy != "" {
		result.Details = append(result.Details, fmt.Sprintf("✓ Default policy: %s", defaultPolicy))
		if defaultPolicy == "deny" {
			result.Details = append(result.Details, "  (secure: deny-by-default)")
		} else if defaultPolicy == "allow" {
			result.Details = append(result.Details, "  (warning: allow-by-default is less secure)")
		}
	}

	// Check for token persistence
	if strings.Contains(configStr, "enable_token_persistence = true") {
		result.Details = append(result.Details, "✓ Token persistence enabled")
	}

	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "Next steps:")
	result.Details = append(result.Details, "  1. Bootstrap ACLs: eos update consul --bootstrap-token")
	result.Details = append(result.Details, "  2. Create policies: consul acl policy create ...")
	result.Details = append(result.Details, "  3. Create tokens: consul acl token create ...")

	return result
}

// checkDataDirectoryConfiguration verifies that the configured data directory
// matches the actual data directory where Consul is storing Raft state.
//
// This check is CRITICAL for ACL bootstrap reset operations, which write
// acl-bootstrap-reset files to the data directory. If the configured path
// doesn't match the actual path, Consul never sees the reset file and
// bootstrap fails.
//
// Evidence gathered:
//  1. Configured data_dir from config file
//  2. Configured data_dir from process arguments
//  3. Configured data_dir from Consul API
//  4. Actual data_dir by finding active raft/raft.db file
//  5. Orphaned ACL reset files (proof Consul didn't consume them)
//
// Returns:
//   - SUCCESS: Config matches actual, no orphaned files
//   - WARNING: Multiple sources disagree, but no active mismatch
//   - CRITICAL: Config doesn't match actual (ACL operations will fail)
func checkDataDirectoryConfiguration(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking data directory configuration vs. actual usage")

	result := DiagnosticResult{
		CheckName: "Data Directory Configuration",
		Success:   true,
		Details:   []string{},
	}

	// ========================================================================
	// ASSESS - Detect CONFIGURED data directory from multiple sources
	// ========================================================================

	result.Details = append(result.Details, "=== Configured Data Directory (from various sources) ===")

	// Source 1: Config file
	var configDataDir string
	configPath := consul.ConsulConfigFile
	if content, err := os.ReadFile(configPath); err == nil {
		configStr := string(content)
		// Parse: data_dir = "/path/to/dir"
		if matches := regexp.MustCompile(`data_dir\s*=\s*"([^"]+)"`).FindStringSubmatch(configStr); len(matches) > 1 {
			configDataDir = matches[1]
			result.Details = append(result.Details, fmt.Sprintf("Config file (%s): %s", configPath, configDataDir))
		} else {
			result.Details = append(result.Details, fmt.Sprintf("Config file (%s): NOT SPECIFIED", configPath))
		}
	} else {
		result.Details = append(result.Details, fmt.Sprintf("Config file (%s): UNREADABLE", configPath))
	}

	// Source 2: Process arguments
	var processDataDir string
	cmd := execute.Options{
		Command: "ps",
		Args:    []string{"aux"},
		Capture: true,
	}
	if output, err := execute.Run(rc.Ctx, cmd); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "consul agent") && !strings.Contains(line, "grep") {
				// Extract -data-dir flag
				if matches := regexp.MustCompile(`-data-dir[= ]([^\s]+)`).FindStringSubmatch(line); len(matches) > 1 {
					processDataDir = strings.Trim(matches[1], `"'`)
					result.Details = append(result.Details, fmt.Sprintf("Process arguments (ps aux): %s", processDataDir))
					break
				}
			}
		}
		if processDataDir == "" {
			result.Details = append(result.Details, "Process arguments (ps aux): NOT SPECIFIED")
		}
	} else {
		result.Details = append(result.Details, "Process arguments (ps aux): UNAVAILABLE")
	}

	// Source 3: Consul API
	var apiDataDir string
	consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
	if err == nil {
		if agentSelf, err := consulClient.Agent().Self(); err == nil {
			if configMap, ok := agentSelf["Config"]; ok {
				if dataDir, ok := configMap["DataDir"].(string); ok && dataDir != "" {
					apiDataDir = dataDir
					result.Details = append(result.Details, fmt.Sprintf("API query (/v1/agent/self): %s", apiDataDir))
				}
			}
		}
	}
	if apiDataDir == "" {
		result.Details = append(result.Details, "API query (/v1/agent/self): UNAVAILABLE (expected if ACLs locked)")
	}

	// Source 4: Systemd service file
	var systemdDataDir string
	serviceFile := "/etc/systemd/system/consul.service"
	if content, err := os.ReadFile(serviceFile); err == nil {
		serviceStr := string(content)
		if matches := regexp.MustCompile(`-data-dir[= ]([^\s]+)`).FindStringSubmatch(serviceStr); len(matches) > 1 {
			systemdDataDir = strings.Trim(matches[1], `"'`)
			result.Details = append(result.Details, fmt.Sprintf("Systemd service (%s): %s", serviceFile, systemdDataDir))
		}
	}
	if systemdDataDir == "" {
		result.Details = append(result.Details, fmt.Sprintf("Systemd service (%s): NOT SPECIFIED", serviceFile))
	}

	// Source 5: Journalctl logs
	var logDataDir string
	logCmd := execute.Options{
		Command: "journalctl",
		Args:    []string{"-u", "consul", "--no-pager", "--since", "24 hours ago"},
		Capture: true,
	}
	if logOutput, err := execute.Run(rc.Ctx, logCmd); err == nil {
		// Look for startup messages mentioning data_dir
		if matches := regexp.MustCompile(`data.dir[=:]?\s*([^\s,]+)`).FindStringSubmatch(logOutput); len(matches) > 1 {
			logDataDir = strings.Trim(matches[1], `"'`)
			result.Details = append(result.Details, fmt.Sprintf("Consul logs (journalctl): %s", logDataDir))
		}
	}
	if logDataDir == "" {
		result.Details = append(result.Details, "Consul logs (journalctl): NOT FOUND")
	}

	result.Details = append(result.Details, "")

	// ========================================================================
	// ASSESS - Detect ACTUAL data directory by finding active raft.db
	// ========================================================================

	result.Details = append(result.Details, "=== Actual Data Directory (active Raft database) ===")

	type raftInfo struct {
		path     string
		size     int64
		mtime    time.Time
		ageHours float64
	}

	var raftDBs []raftInfo

	// Check common paths for active raft.db
	candidatePaths := []string{
		"/opt/consul",
		"/var/lib/consul",
		"/data/consul",
		"/consul/data",
	}

	// Also add configured paths if they're different
	if configDataDir != "" && !contains(candidatePaths, configDataDir) {
		candidatePaths = append(candidatePaths, configDataDir)
	}
	if processDataDir != "" && !contains(candidatePaths, processDataDir) {
		candidatePaths = append(candidatePaths, processDataDir)
	}
	if apiDataDir != "" && !contains(candidatePaths, apiDataDir) {
		candidatePaths = append(candidatePaths, apiDataDir)
	}

	for _, basePath := range candidatePaths {
		raftDBPath := filepath.Join(basePath, "raft", "raft.db")
		if info, err := os.Stat(raftDBPath); err == nil {
			age := time.Since(info.ModTime())
			raftDBs = append(raftDBs, raftInfo{
				path:     raftDBPath,
				size:     info.Size(),
				mtime:    info.ModTime(),
				ageHours: age.Hours(),
			})
		}
	}

	var activeDataDir string
	if len(raftDBs) == 0 {
		result.Details = append(result.Details, "✗ No raft.db found in any checked location")
		result.Details = append(result.Details, fmt.Sprintf("  Checked: %v", candidatePaths))
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Cannot locate Consul's active data directory"
		return result
	}

	// Find the most recently modified raft.db (the active one)
	var mostRecent raftInfo
	for _, db := range raftDBs {
		if mostRecent.path == "" || db.mtime.After(mostRecent.mtime) {
			mostRecent = db
		}

		// Report all found raft.db files
		activeMarker := ""
		if db.ageHours < 1.0 {
			activeMarker = " (ACTIVE - modified within 1 hour)"
		} else if db.ageHours < 24.0 {
			activeMarker = fmt.Sprintf(" (modified %.1f hours ago)", db.ageHours)
		} else {
			activeMarker = fmt.Sprintf(" (STALE - modified %.1f hours ago)", db.ageHours)
		}
		result.Details = append(result.Details,
			fmt.Sprintf("  %s: %d bytes, mtime=%s%s",
				db.path,
				db.size,
				db.mtime.Format("2006-01-02 15:04:05"),
				activeMarker))
	}

	// Determine active data directory from most recent raft.db
	activeDataDir = filepath.Dir(filepath.Dir(mostRecent.path)) // /path/to/consul/raft/raft.db → /path/to/consul

	if mostRecent.ageHours < 1.0 {
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, fmt.Sprintf("✓ Active data directory: %s", activeDataDir))
	} else {
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, fmt.Sprintf("⚠ Likely data directory: %s (raft.db is stale)", activeDataDir))
	}

	result.Details = append(result.Details, "")

	// ========================================================================
	// ASSESS - Check for orphaned ACL reset files
	// ========================================================================

	result.Details = append(result.Details, "=== ACL Bootstrap Reset File Status ===")

	orphanedResetFiles := []string{}
	for _, basePath := range candidatePaths {
		resetFilePath := filepath.Join(basePath, "acl-bootstrap-reset")
		if info, err := os.Stat(resetFilePath); err == nil {
			// File exists!
			age := time.Since(info.ModTime())
			orphanedResetFiles = append(orphanedResetFiles, resetFilePath)

			// Read contents
			if content, err := os.ReadFile(resetFilePath); err == nil {
				result.Details = append(result.Details,
					fmt.Sprintf("✗ ORPHANED reset file found: %s", resetFilePath))
				result.Details = append(result.Details,
					fmt.Sprintf("  Contents: %s", strings.TrimSpace(string(content))))
				result.Details = append(result.Details,
					fmt.Sprintf("  Age: %.1f hours", age.Hours()))
				result.Details = append(result.Details,
					"  This file was written but Consul NEVER consumed it")
				result.Details = append(result.Details,
					"  Proof: If Consul had consumed it, the file would be deleted")
			}
		}
	}

	if len(orphanedResetFiles) == 0 {
		result.Details = append(result.Details, "✓ No orphaned ACL reset files found")
	}

	result.Details = append(result.Details, "")

	// ========================================================================
	// EVALUATE - Compare configured vs. actual and report mismatches
	// ========================================================================

	result.Details = append(result.Details, "=== Configuration Analysis ===")

	// Collect all non-empty configured paths
	configuredPaths := make(map[string][]string) // path -> sources
	if configDataDir != "" {
		configuredPaths[configDataDir] = append(configuredPaths[configDataDir], "config_file")
	}
	if processDataDir != "" {
		configuredPaths[processDataDir] = append(configuredPaths[processDataDir], "process_args")
	}
	if apiDataDir != "" {
		configuredPaths[apiDataDir] = append(configuredPaths[apiDataDir], "api")
	}
	if systemdDataDir != "" {
		configuredPaths[systemdDataDir] = append(configuredPaths[systemdDataDir], "systemd")
	}
	if logDataDir != "" {
		configuredPaths[logDataDir] = append(configuredPaths[logDataDir], "logs")
	}

	// Check if all sources agree
	if len(configuredPaths) == 0 {
		result.Details = append(result.Details, "⚠ WARNING: No data directory configured anywhere")
		result.Details = append(result.Details, "  Consul is likely using compiled-in defaults")
		result.Success = false
		result.Severity = SeverityWarning
	} else if len(configuredPaths) == 1 {
		// All sources agree - check if it matches actual
		var configuredPath string
		var sources []string
		for path, srcs := range configuredPaths {
			configuredPath = path
			sources = srcs
		}

		if configuredPath == activeDataDir {
			result.Details = append(result.Details, "✓ SUCCESS: Configuration matches actual data directory")
			result.Details = append(result.Details, fmt.Sprintf("  Path: %s", activeDataDir))
			result.Details = append(result.Details, fmt.Sprintf("  Sources agree: %v", sources))
		} else {
			result.Details = append(result.Details, "✗ CRITICAL MISMATCH DETECTED")
			result.Details = append(result.Details, fmt.Sprintf("  Configured: %s (from %v)", configuredPath, sources))
			result.Details = append(result.Details, fmt.Sprintf("  Actual:     %s (active raft.db location)", activeDataDir))
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "IMPACT:")
			result.Details = append(result.Details, "  - ACL bootstrap reset will FAIL (writes to wrong directory)")
			result.Details = append(result.Details, "  - Consul reads from: "+activeDataDir)
			result.Details = append(result.Details, "  - Reset file written to: "+configuredPath)
			result.Details = append(result.Details, "  - Consul never sees the file → bootstrap fails")

			result.Success = false
			result.Severity = SeverityCritical
			result.Message = "Data directory configuration doesn't match actual usage"
		}
	} else {
		// Multiple different paths configured - this is confusing
		result.Details = append(result.Details, "⚠ WARNING: Multiple sources specify DIFFERENT data directories")
		for path, sources := range configuredPaths {
			matchMarker := ""
			if path == activeDataDir {
				matchMarker = " ← MATCHES ACTUAL"
			}
			result.Details = append(result.Details, fmt.Sprintf("  %s: %v%s", path, sources, matchMarker))
		}
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, fmt.Sprintf("Active data directory (raft.db): %s", activeDataDir))

		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Inconsistent data directory configuration across sources"
	}

	// If orphaned files exist, definitely a problem
	if len(orphanedResetFiles) > 0 {
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "✗ ORPHANED ACL RESET FILES DETECTED")
		result.Details = append(result.Details, "  These files were written but Consul never consumed them.")
		result.Details = append(result.Details, "  This is PROOF that the reset file was written to the WRONG directory.")
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Data directory mismatch confirmed by orphaned reset files"
	}

	// ========================================================================
	// EVALUATE - Provide remediation guidance
	// ========================================================================

	if !result.Success {
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")

		if len(orphanedResetFiles) > 0 {
			result.Details = append(result.Details, "  1. Clean up orphaned reset files:")
			for _, file := range orphanedResetFiles {
				result.Details = append(result.Details, fmt.Sprintf("       sudo rm %s", file))
			}
			result.Details = append(result.Details, "")
		}

		if result.Severity == SeverityCritical {
			// Provide specific fix for mismatch
			var wrongPath string
			for path := range configuredPaths {
				if path != activeDataDir {
					wrongPath = path
					break
				}
			}

			if wrongPath != "" && configDataDir != "" && configDataDir != activeDataDir {
				result.Details = append(result.Details, fmt.Sprintf("  2. Fix config file to use actual data directory:"))
				result.Details = append(result.Details, fmt.Sprintf("       Edit: %s", consul.ConsulConfigFile))
				result.Details = append(result.Details, fmt.Sprintf("       Change: data_dir = \"%s\"", configDataDir))
				result.Details = append(result.Details, fmt.Sprintf("       To:     data_dir = \"%s\"", activeDataDir))
				result.Details = append(result.Details, "")
				result.Details = append(result.Details, "  3. Restart Consul:")
				result.Details = append(result.Details, "       sudo systemctl restart consul")
			}

			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "  4. Use explicit --data-dir when running ACL bootstrap:")
			result.Details = append(result.Details, fmt.Sprintf("       sudo eos update consul --bootstrap-token --data-dir %s", activeDataDir))
		}
	}

	if result.Success {
		result.Message = "Data directory configuration is correct"
	}

	return result
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// checkDataDirectoryFileSystem verifies the actual data directory exists on the filesystem
// and lists its contents. This provides evidence of whether Consul has initialized the
// data directory and what files it contains.
//
// CRITICAL for debugging ACL bootstrap reset failures:
//   - Confirms data directory actually exists on disk (not just in config)
//   - Shows if raft/ subdirectory exists (required for Consul to start)
//   - Shows if acl-bootstrap-reset file exists (orphaned reset attempts)
//   - Shows if raft.db exists (Raft state database)
//
// Returns:
//   - SUCCESS: Data directory exists and contains expected structure
//   - WARNING: Data directory exists but missing expected files
//   - CRITICAL: Data directory doesn't exist on filesystem
func checkDataDirectoryFileSystem(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking actual data directory filesystem state")

	result := DiagnosticResult{
		CheckName: "Data Directory FileSystem",
		Success:   true,
		Details:   []string{},
	}

	// ASSESS - Try to determine data directory from config
	configPath := consul.ConsulConfigFile
	var configuredDataDir string

	if content, err := os.ReadFile(configPath); err == nil {
		configStr := string(content)
		if matches := regexp.MustCompile(`data_dir\s*=\s*"([^"]+)"`).FindStringSubmatch(configStr); len(matches) > 1 {
			configuredDataDir = matches[1]
			result.Details = append(result.Details, fmt.Sprintf("Configured data_dir: %s", configuredDataDir))
		}
	}

	// Fallback to default if not configured
	if configuredDataDir == "" {
		configuredDataDir = "/opt/consul"
		result.Details = append(result.Details, "No data_dir in config, using default: /opt/consul")
	}

	result.Details = append(result.Details, "")

	// ASSESS - Check if directory exists
	dirInfo, err := os.Stat(configuredDataDir)
	if err != nil {
		if os.IsNotExist(err) {
			result.Success = false
			result.Severity = SeverityCritical
			result.Message = "Data directory does not exist on filesystem"
			result.Details = append(result.Details, fmt.Sprintf("✗ Directory not found: %s", configuredDataDir))
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "IMPACT:")
			result.Details = append(result.Details, "  - Consul cannot start without data directory")
			result.Details = append(result.Details, "  - ACL bootstrap reset will fail")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "REMEDIATION:")
			result.Details = append(result.Details, fmt.Sprintf("  sudo mkdir -p %s", configuredDataDir))
			result.Details = append(result.Details, "  sudo chown consul:consul "+configuredDataDir)
			result.Details = append(result.Details, "  sudo chmod 0750 "+configuredDataDir)
			return result
		}
		result.Success = false
		result.Message = fmt.Sprintf("Cannot access data directory: %v", err)
		result.Details = append(result.Details, fmt.Sprintf("✗ Error accessing %s: %v", configuredDataDir, err))
		return result
	}

	// Verify it's a directory
	if !dirInfo.IsDir() {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Data directory path exists but is not a directory"
		result.Details = append(result.Details, fmt.Sprintf("✗ %s exists but is a FILE, not a directory", configuredDataDir))
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("✓ Data directory exists: %s", configuredDataDir))

	// Show permissions and ownership
	stat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if ok {
		result.Details = append(result.Details, fmt.Sprintf("  Permissions: %04o", dirInfo.Mode().Perm()))
		result.Details = append(result.Details, fmt.Sprintf("  Owner UID/GID: %d:%d", stat.Uid, stat.Gid))
	}

	result.Details = append(result.Details, "")

	// ASSESS - List directory contents
	result.Details = append(result.Details, "Directory contents:")

	entries, err := os.ReadDir(configuredDataDir)
	if err != nil {
		result.Details = append(result.Details, fmt.Sprintf("✗ Cannot read directory: %v", err))
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Data directory exists but cannot read contents"
		return result
	}

	if len(entries) == 0 {
		result.Details = append(result.Details, "  (empty directory)")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "⚠ Data directory is empty - Consul has not initialized yet")
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Data directory is empty (Consul not initialized)"
		return result
	}

	// List all entries with details
	hasRaftDir := false
	hasRaftDB := false
	hasACLResetFile := false
	aclResetFilePath := ""

	for _, entry := range entries {
		entryPath := filepath.Join(configuredDataDir, entry.Name())
		entryInfo, err := entry.Info()
		if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("  %s (cannot stat)", entry.Name()))
			continue
		}

		entryType := "file"
		if entry.IsDir() {
			entryType = "dir"
		}

		result.Details = append(result.Details,
			fmt.Sprintf("  %s (%s, %d bytes, mtime=%s)",
				entry.Name(),
				entryType,
				entryInfo.Size(),
				entryInfo.ModTime().Format("2006-01-02 15:04:05")))

		// Track important files/directories
		if entry.Name() == "raft" && entry.IsDir() {
			hasRaftDir = true
		}
		if entry.Name() == "acl-bootstrap-reset" {
			hasACLResetFile = true
			aclResetFilePath = entryPath
		}
	}

	// Check for raft.db inside raft/ subdirectory
	if hasRaftDir {
		raftDBPath := filepath.Join(configuredDataDir, "raft", "raft.db")
		if _, err := os.Stat(raftDBPath); err == nil {
			hasRaftDB = true
			result.Details = append(result.Details, "  raft/raft.db (Raft state database found)")
		}
	}

	result.Details = append(result.Details, "")

	// EVALUATE - Check for expected structure
	if !hasRaftDir {
		result.Details = append(result.Details, "⚠ Missing raft/ subdirectory")
		result.Details = append(result.Details, "  Consul may not have started successfully yet")
		result.Success = false
		result.Severity = SeverityWarning
	}

	if hasRaftDir && !hasRaftDB {
		result.Details = append(result.Details, "⚠ raft/ directory exists but raft.db is missing")
		result.Details = append(result.Details, "  Consul Raft database not initialized")
		result.Success = false
		result.Severity = SeverityWarning
	}

	if hasACLResetFile {
		result.Details = append(result.Details, "✗ ORPHANED acl-bootstrap-reset file detected!")
		// Read contents
		if content, err := os.ReadFile(aclResetFilePath); err == nil {
			result.Details = append(result.Details, fmt.Sprintf("  Contents: %s", strings.TrimSpace(string(content))))
		}
		result.Details = append(result.Details, "  This file should have been consumed by Consul")
		result.Details = append(result.Details, "  Consul deletes this file after reading it")
		result.Details = append(result.Details, "  Presence indicates Consul NEVER SAW this file")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		result.Details = append(result.Details, fmt.Sprintf("  sudo rm %s", aclResetFilePath))
		result.Success = false
		result.Severity = SeverityWarning
	}

	// Set message based on findings
	if result.Success {
		result.Message = "Data directory exists and contains expected structure"
	}

	return result
}

// checkRaftDatabase searches for all raft.db files on the system to detect
// potential data directory mismatches or multiple Consul instances.
//
// CRITICAL for debugging ACL bootstrap reset failures:
//   - Finds the ACTUAL active raft.db (most recently modified)
//   - Detects stale/orphaned raft.db files from previous installations
//   - Confirms which data directory Consul is REALLY using
//   - Evidence: If configured data_dir has no raft.db, config is wrong
//
// Returns:
//   - SUCCESS: Found exactly one active raft.db matching config
//   - WARNING: Found multiple raft.db files (stale installations)
//   - CRITICAL: No raft.db found anywhere (Consul never started)
func checkRaftDatabase(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Searching for Raft database files across filesystem")

	result := DiagnosticResult{
		CheckName: "Raft Database Location",
		Success:   true,
		Details:   []string{},
	}

	// ASSESS - Get configured data directory
	configPath := consul.ConsulConfigFile
	var configuredDataDir string

	if content, err := os.ReadFile(configPath); err == nil {
		configStr := string(content)
		if matches := regexp.MustCompile(`data_dir\s*=\s*"([^"]+)"`).FindStringSubmatch(configStr); len(matches) > 1 {
			configuredDataDir = matches[1]
		}
	}

	if configuredDataDir == "" {
		configuredDataDir = "/opt/consul"
	}

	result.Details = append(result.Details, fmt.Sprintf("Configured data_dir: %s", configuredDataDir))
	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "Searching for raft.db files...")
	result.Details = append(result.Details, "")

	// ASSESS - Search common locations for raft.db
	searchPaths := []string{
		"/opt/consul",
		"/var/lib/consul",
		"/data/consul",
		"/consul/data",
		"/tmp/consul", // Sometimes used for testing
	}

	// Add configured path if different
	if !contains(searchPaths, configuredDataDir) {
		searchPaths = append(searchPaths, configuredDataDir)
	}

	type raftDBInfo struct {
		path          string
		size          int64
		mtime         time.Time
		ageHours      float64
		isActive      bool
		matchesConfig bool
	}

	var foundRaftDBs []raftDBInfo

	for _, basePath := range searchPaths {
		raftPath := filepath.Join(basePath, "raft", "raft.db")
		info, err := os.Stat(raftPath)
		if err != nil {
			continue // File doesn't exist, skip
		}

		age := time.Since(info.ModTime())
		isActive := age.Hours() < 1.0 // Modified within last hour = likely active
		matchesConfig := (basePath == configuredDataDir)

		foundRaftDBs = append(foundRaftDBs, raftDBInfo{
			path:          raftPath,
			size:          info.Size(),
			mtime:         info.ModTime(),
			ageHours:      age.Hours(),
			isActive:      isActive,
			matchesConfig: matchesConfig,
		})
	}

	// EVALUATE - Analyze findings
	if len(foundRaftDBs) == 0 {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "No raft.db found anywhere on filesystem"
		result.Details = append(result.Details, "✗ No raft.db files found in any common location")
		result.Details = append(result.Details, fmt.Sprintf("  Searched: %v", searchPaths))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "IMPACT:")
		result.Details = append(result.Details, "  - Consul has never successfully started")
		result.Details = append(result.Details, "  - Raft consensus database not initialized")
		result.Details = append(result.Details, "  - Cannot bootstrap ACLs without Raft")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		result.Details = append(result.Details, "  1. Check Consul is running: sudo systemctl status consul")
		result.Details = append(result.Details, "  2. Check Consul logs: sudo journalctl -u consul -n 100")
		result.Details = append(result.Details, "  3. Fix startup issues, then Consul will create raft.db")
		return result
	}

	// Report all found raft.db files
	result.Details = append(result.Details, fmt.Sprintf("Found %d raft.db file(s):", len(foundRaftDBs)))
	result.Details = append(result.Details, "")

	var activeDB *raftDBInfo
	configMatchDB := false

	for i := range foundRaftDBs {
		db := &foundRaftDBs[i]

		status := ""
		if db.isActive {
			status = "ACTIVE (modified < 1 hour ago)"
			activeDB = db
		} else if db.ageHours < 24 {
			status = fmt.Sprintf("Recent (%.1fh ago)", db.ageHours)
		} else {
			status = fmt.Sprintf("STALE (%.0fh ago)", db.ageHours)
		}

		configMarker := ""
		if db.matchesConfig {
			configMarker = " ← Matches configured data_dir"
			configMatchDB = true
		}

		result.Details = append(result.Details,
			fmt.Sprintf("  %s", db.path))
		result.Details = append(result.Details,
			fmt.Sprintf("    Size: %d bytes", db.size))
		result.Details = append(result.Details,
			fmt.Sprintf("    Modified: %s (%s)%s",
				db.mtime.Format("2006-01-02 15:04:05"),
				status,
				configMarker))
		result.Details = append(result.Details, "")
	}

	// EVALUATE - Check for issues
	if len(foundRaftDBs) > 1 {
		result.Details = append(result.Details, "⚠ WARNING: Multiple raft.db files found")
		result.Details = append(result.Details, "  This suggests:")
		result.Details = append(result.Details, "    - Previous Consul installations not cleaned up")
		result.Details = append(result.Details, "    - OR data_dir was changed and old data remains")
		result.Details = append(result.Details, "")
		result.Success = false
		result.Severity = SeverityWarning
	}

	if activeDB != nil && !activeDB.matchesConfig {
		result.Details = append(result.Details, "✗ CRITICAL: Active raft.db DOES NOT match configured data_dir!")
		result.Details = append(result.Details, fmt.Sprintf("  Active raft.db: %s", activeDB.path))
		result.Details = append(result.Details, fmt.Sprintf("  Configured:     %s/raft/raft.db", configuredDataDir))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "IMPACT:")
		result.Details = append(result.Details, "  - Consul is reading from: "+filepath.Dir(filepath.Dir(activeDB.path)))
		result.Details = append(result.Details, "  - Config says to use:     "+configuredDataDir)
		result.Details = append(result.Details, "  - ACL reset file written to WRONG directory")
		result.Details = append(result.Details, "  - Consul never sees reset file → bootstrap fails")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		actualDataDir := filepath.Dir(filepath.Dir(activeDB.path))
		result.Details = append(result.Details, fmt.Sprintf("  Option 1: Update config to match actual data_dir:"))
		result.Details = append(result.Details, fmt.Sprintf("    Edit %s", consul.ConsulConfigFile))
		result.Details = append(result.Details, fmt.Sprintf("    Set: data_dir = \"%s\"", actualDataDir))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "  Option 2: Use explicit --data-dir flag:")
		result.Details = append(result.Details, fmt.Sprintf("    sudo eos update consul --bootstrap-token --data-dir %s", actualDataDir))
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Active raft.db does not match configured data directory"
		return result
	}

	if !configMatchDB {
		result.Details = append(result.Details, "⚠ No raft.db found in configured data_dir")
		result.Details = append(result.Details, fmt.Sprintf("  Expected: %s/raft/raft.db", configuredDataDir))
		result.Details = append(result.Details, "  This suggests Consul is NOT using the configured data_dir")
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "No raft.db in configured data directory"
		return result
	}

	// SUCCESS
	result.Message = "Raft database found and matches configuration"
	if activeDB != nil {
		result.Details = append(result.Details, "✓ Active raft.db matches configured data_dir")
		result.Details = append(result.Details, "  ACL bootstrap reset will write to correct location")
	}

	return result
}

// checkRecentACLBootstrapActivity checks journalctl logs for recent ACL bootstrap
// attempts, errors, and reset activity.
//
// CRITICAL for debugging ACL bootstrap reset failures:
//   - Shows if Consul saw the acl-bootstrap-reset file
//   - Shows if Consul consumed the reset file
//   - Shows ACL bootstrap errors (invalid reset index, permission denied, etc.)
//   - Shows if bootstrap succeeded and what the reset index was
//
// Returns:
//   - SUCCESS: Logs show clean bootstrap history
//   - WARNING: Found bootstrap errors in logs
//   - INFO: Recent bootstrap attempts detected (informational)
func checkRecentACLBootstrapActivity(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking recent ACL bootstrap activity in Consul logs")

	result := DiagnosticResult{
		CheckName: "ACL Bootstrap Log Activity",
		Success:   true,
		Details:   []string{},
	}

	// ASSESS - Get recent Consul logs
	cmd := execute.Options{
		Command: "journalctl",
		Args:    []string{"-u", "consul", "--since", "5 minutes ago", "--no-pager"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Message = "Cannot access Consul logs via journalctl"
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		result.Details = append(result.Details, "  Check if running as root: sudo eos debug consul")
		result.Details = append(result.Details, "  Or check journald permissions")
		result.Success = false
		result.Severity = SeverityWarning
		return result
	}

	if strings.TrimSpace(output) == "" {
		result.Message = "No recent Consul logs found (last 5 minutes)"
		result.Details = append(result.Details, "Consul may not have been active recently")
		result.Details = append(result.Details, "Extend time range: journalctl -u consul --since '1 hour ago'")
		return result
	}

	// ASSESS - Search for ACL-related log patterns
	patterns := map[string]string{
		"bootstrap":           "ACL bootstrap attempts",
		"acl-bootstrap-reset": "ACL reset file activity",
		"reset index":         "Reset index operations",
		"Invalid bootstrap":   "Bootstrap errors",
		"ACL replication":     "ACL replication activity",
		"Permission denied":   "ACL permission errors",
	}

	foundPatterns := make(map[string][]string) // pattern -> matching log lines

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		for pattern, description := range patterns {
			if strings.Contains(lineLower, strings.ToLower(pattern)) {
				foundPatterns[description] = append(foundPatterns[description], strings.TrimSpace(line))
			}
		}
	}

	result.Details = append(result.Details, "Recent Consul logs (last 5 minutes):")
	result.Details = append(result.Details, "")

	if len(foundPatterns) == 0 {
		result.Message = "No ACL bootstrap activity found in recent logs"
		result.Details = append(result.Details, "✓ No ACL-related log entries in the last 5 minutes")
		result.Details = append(result.Details, "  This is normal if ACL operations haven't been performed recently")
		return result
	}

	// EVALUATE - Report findings
	hasErrors := false
	for description, logLines := range foundPatterns {
		result.Details = append(result.Details, fmt.Sprintf("=== %s ===", description))

		// Show up to 10 most recent lines per pattern
		displayCount := len(logLines)
		if displayCount > 10 {
			displayCount = 10
		}

		for i := 0; i < displayCount; i++ {
			result.Details = append(result.Details, logLines[i])
		}

		if len(logLines) > 10 {
			result.Details = append(result.Details, fmt.Sprintf("  ... and %d more lines", len(logLines)-10))
		}

		result.Details = append(result.Details, "")

		// Check if this pattern indicates an error
		if strings.Contains(description, "error") || strings.Contains(description, "denied") {
			hasErrors = true
		}
	}

	// EVALUATE - Set severity based on findings
	if hasErrors {
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Found ACL bootstrap errors in recent logs"
	} else {
		result.Message = "Found ACL bootstrap activity in recent logs"
		result.Severity = SeverityInfo // Informational, not an error
	}

	// EVALUATE - Provide context
	result.Details = append(result.Details, "ANALYSIS:")

	if logs, ok := foundPatterns["ACL reset file activity"]; ok && len(logs) > 0 {
		result.Details = append(result.Details, "  ✓ Consul saw the acl-bootstrap-reset file")
		result.Details = append(result.Details, "    (logs mention acl-bootstrap-reset)")
	}

	if logs, ok := foundPatterns["Reset index operations"]; ok && len(logs) > 0 {
		result.Details = append(result.Details, "  ✓ Consul processed reset index")
		result.Details = append(result.Details, "    (logs mention 'reset index')")
	}

	if logs, ok := foundPatterns["Bootstrap errors"]; ok && len(logs) > 0 {
		result.Details = append(result.Details, "  ✗ Bootstrap failed with errors")
		result.Details = append(result.Details, "    Check 'Invalid bootstrap' section above for details")
	}

	return result
}
