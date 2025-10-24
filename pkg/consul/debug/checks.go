package debug

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
			result.Success = false
			result.Details = append(result.Details,
				fmt.Sprintf("Port %d (%s) is already in use", port, name))

			// Try to identify what's using the port
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.Contains(line, portStr) {
					result.Details = append(result.Details, "  "+strings.TrimSpace(line))
				}
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("Port %d (%s) is available", port, name))
		}
	}

	if result.Success {
		result.Message = "All Consul ports are available"
	} else {
		result.Message = "One or more Consul ports are already in use"
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

	// Check for any consul processes
	cmd := execute.Options{
		Command: "ps",
		Args:    []string{"aux"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Message = "Could not check for processes"
		return result
	}

	// Look for consul processes
	lines := strings.Split(output, "\n")
	consulProcesses := []string{}

	for _, line := range lines {
		if strings.Contains(line, "consul") && !strings.Contains(line, "grep") {
			consulProcesses = append(consulProcesses, strings.TrimSpace(line))
		}
	}

	if len(consulProcesses) > 0 {
		result.Success = false
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

	binPath := "/usr/local/bin/consul"

	// Check if binary exists
	info, err := os.Stat(binPath)
	if err != nil {
		result.Success = false
		result.Message = "Consul binary not found"
		result.Details = append(result.Details, fmt.Sprintf("Expected path: %s", binPath))
		return result
	}

	// Check permissions
	mode := info.Mode()
	if mode&0111 == 0 {
		result.Success = false
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

// checkConsulPermissions verifies file permissions for Consul directories
func checkConsulPermissions(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Consul file permissions")

	result := DiagnosticResult{
		CheckName: "File Permissions",
		Success:   true,
		Details:   []string{},
	}

	// Paths to check
	paths := map[string]string{
		"/etc/consul.d":       "config directory",
		"/opt/consul":         "data directory",
		"/var/log/consul.log": "log file",
	}

	for path, description := range paths {
		info, err := os.Stat(path)
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("✗ %s (%s): Does not exist", description, path))
			continue
		}

		mode := info.Mode()
		result.Details = append(result.Details,
			fmt.Sprintf("✓ %s (%s): %s", description, path, mode))
	}

	result.Message = "File permission check completed"
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
		result.Message = fmt.Sprintf("Found %d issue(s) in logs", len(foundIssues))
		result.Details = append([]string{"Issues detected:"}, foundIssues...)
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

	configPath := "/etc/consul.d/consul.hcl"

	// Check if config file exists
	if _, err := os.Stat(configPath); err != nil {
		result.Success = false
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
		result.Message = fmt.Sprintf("Found %d configuration issue(s)", len(issues))
		for _, issue := range issues {
			result.Details = append(result.Details, "• "+issue)
		}
	} else {
		result.Message = "Configuration appears valid"

		// Run consul validate for additional checks
		validateCmd := execute.Options{
			Command: "/usr/local/bin/consul",
			Args:    []string{"validate", "/etc/consul.d/"},
			Capture: true,
		}

		output, err := execute.Run(rc.Ctx, validateCmd)
		if err != nil {
			result.Success = false
			result.Details = append(result.Details, "Consul validate failed: "+output)
		} else {
			result.Details = append(result.Details, "Consul validate passed")
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
		addr := fmt.Sprintf("%s:%d", shared.GetInternalHostname(), port)
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
		apiURL := fmt.Sprintf("http://%s:%d/v1/agent/self", shared.GetInternalHostname(), shared.PortConsul)
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
		result.Message = "Consul HTTP API port not listening"
	}

	return result
}

// checkVaultConsulConnectivity checks if Vault can reach Consul (critical for Vault storage backend)
func checkVaultConsulConnectivity(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Vault-Consul connectivity")

	result := DiagnosticResult{
		CheckName: "Vault-Consul Connectivity",
		Success:   true,
		Details:   []string{},
	}

	// STEP 1: Check /etc/hosts for hostname resolution
	logger.Debug("Checking /etc/hosts for hostname resolution")
	hostsCmd := execute.Options{
		Command: "cat",
		Args:    []string{"/etc/hosts"},
		Capture: true,
	}
	hostsOutput, err := execute.Run(rc.Ctx, hostsCmd)
	if err != nil {
		result.Details = append(result.Details, "⚠ Could not read /etc/hosts")
	} else {
		hostname := shared.GetInternalHostname()
		result.Details = append(result.Details, fmt.Sprintf("Checking hostname resolution for: %s", hostname))

		// Parse /etc/hosts for the hostname
		hostsLines := strings.Split(hostsOutput, "\n")
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

						// Check for suspicious 127.0.1.1 mapping
						if ip == "127.0.1.1" {
							result.Details = append(result.Details,
								"  ⚠ WARNING: Hostname maps to 127.0.1.1 (Ubuntu default)")
							result.Details = append(result.Details,
								"    This can cause Vault-Consul connection issues!")
							result.Details = append(result.Details,
								"    Consul might be listening on 127.0.0.1, but Vault resolves to 127.0.1.1")
						}
					}
				}
			}
		}
		if !foundHostname {
			result.Details = append(result.Details, fmt.Sprintf("  ⚠ %s not found in /etc/hosts", hostname))
		}
	}

	// STEP 2: Check what addresses Consul is ACTUALLY listening on
	logger.Debug("Checking Consul listening addresses")
	ssCmd := execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp"},
		Capture: true,
	}
	ssOutput, err := execute.Run(rc.Ctx, ssCmd)
	if err != nil {
		// Fallback to netstat
		netstatCmd := execute.Options{
			Command: "netstat",
			Args:    []string{"-tlnp"},
			Capture: true,
		}
		ssOutput, err = execute.Run(rc.Ctx, netstatCmd)
	}

	if err == nil {
		result.Details = append(result.Details, "\nConsul port 8500 listening addresses:")
		ssLines := strings.Split(ssOutput, "\n")
		found8500 := false
		for _, line := range ssLines {
			if strings.Contains(line, ":8500") && strings.Contains(line, "LISTEN") {
				found8500 = true
				// Extract the local address
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					localAddr := fields[3]
					result.Details = append(result.Details, fmt.Sprintf("  %s", localAddr))
				} else {
					result.Details = append(result.Details, fmt.Sprintf("  %s", strings.TrimSpace(line)))
				}
			}
		}
		if !found8500 {
			result.Success = false
			result.Details = append(result.Details, "  ✗ Consul port 8500 is NOT listening!")
			result.Details = append(result.Details, "    This is why Vault cannot connect to Consul")
		}
	}

	// STEP 3: Check Vault configuration for Consul address
	logger.Debug("Checking Vault configuration for Consul backend")
	vaultConfigPath := "/etc/vault.d/vault.hcl"
	if _, err := os.Stat(vaultConfigPath); err == nil {
		vaultConfigCmd := execute.Options{
			Command: "grep",
			Args:    []string{"-A", "5", `storage "consul"`, vaultConfigPath},
			Capture: true,
		}
		vaultConfigOutput, err := execute.Run(rc.Ctx, vaultConfigCmd)
		if err == nil {
			result.Details = append(result.Details, "\nVault storage backend configuration:")
			configLines := strings.Split(vaultConfigOutput, "\n")
			for _, line := range configLines {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, "address") {
					result.Details = append(result.Details, fmt.Sprintf("  %s", trimmed))

					// Extract the address value
					if strings.Contains(trimmed, "=") {
						parts := strings.Split(trimmed, "=")
						if len(parts) == 2 {
							addr := strings.Trim(strings.TrimSpace(parts[1]), `"`)
							result.Details = append(result.Details,
								fmt.Sprintf("  → Vault will try to connect to: %s", addr))
						}
					}
				}
			}
		}
	} else {
		result.Details = append(result.Details, "\n⚠ Vault config not found at /etc/vault.d/vault.hcl")
	}

	// STEP 4: Test actual connectivity from Vault's perspective
	logger.Debug("Testing Consul connectivity")
	hostname := shared.GetInternalHostname()
	testAddresses := []string{
		fmt.Sprintf("http://127.0.0.1:%d", shared.PortConsul),
		fmt.Sprintf("http://127.0.1.1:%d", shared.PortConsul),
		fmt.Sprintf("http://%s:%d", hostname, shared.PortConsul),
	}

	result.Details = append(result.Details, "\nTesting Consul connectivity from different addresses:")
	anySuccess := false
	for _, addr := range testAddresses {
		client := &http.Client{Timeout: 2 * time.Second}
		apiURL := fmt.Sprintf("%s/v1/agent/self", addr)
		resp, err := client.Get(apiURL)
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			result.Details = append(result.Details, fmt.Sprintf("  ✓ %s: REACHABLE", addr))
			anySuccess = true
		} else {
			result.Details = append(result.Details, fmt.Sprintf("  ✗ %s: %v", addr, err))
		}
	}

	// EVALUATE
	if !anySuccess {
		result.Success = false
		result.Message = "Consul is NOT reachable - Vault storage backend will fail"
		result.Details = append(result.Details, "\n⚠ CRITICAL: Vault cannot connect to Consul storage backend")
		result.Details = append(result.Details, "  This is why 'eos sync consul' authentication fails!")
		result.Details = append(result.Details, "\nRemediation:")
		result.Details = append(result.Details, "  1. Ensure Consul is running: sudo systemctl start consul")
		result.Details = append(result.Details, "  2. Check Consul is listening on correct address")
		result.Details = append(result.Details, "  3. Verify Vault config points to correct Consul address")
	} else {
		result.Message = "Consul is reachable for Vault storage backend"
	}

	return result
}
