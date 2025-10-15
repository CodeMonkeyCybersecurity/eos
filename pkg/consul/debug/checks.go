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
		result.Message = "Failed to check for processes"
		result.Success = false
		return result
	}
	
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
		for _, proc := range consulProcesses {
			// Extract PID from the process line
			fields := strings.Fields(proc)
			if len(fields) > 1 {
				result.Details = append(result.Details, fmt.Sprintf("PID %s: %s", fields[1], proc))
			}
		}
	} else {
		result.Message = "No lingering Consul processes found"
	}
	
	return result
}

// analyzeConfiguration checks the Consul configuration for common issues
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

// checkSystemdService examines the systemd service configuration
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
		result.Message = "Consul service file not found"
		result.Details = append(result.Details, "Service file missing: "+servicePath)
		return result
	}

	result.Details = append(result.Details, "Service file exists: "+servicePath)

	// Read service file
	content, err := os.ReadFile(servicePath)
	if err != nil {
		result.Success = false
		result.Message = "Failed to read service file"
		return result
	}

	serviceStr := string(content)

	// Check for common service issues
	if strings.Contains(serviceStr, "Type=notify") {
		result.Details = append(result.Details,
			"NOTICE: Service uses Type=notify - may cause startup issues with some Consul versions")
	}

	if !strings.Contains(serviceStr, "TimeoutStartSec") {
		result.Details = append(result.Details,
			"NOTICE: No TimeoutStartSec specified - using systemd default (90s)")
	}

	// Check if service is enabled
	cmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"is-enabled", "consul"},
		Capture: true,
	}

	output, _ := execute.Run(rc.Ctx, cmd)
	enabled := strings.TrimSpace(output) == "enabled"

	if enabled {
		result.Details = append(result.Details, "Service is enabled (will start on boot)")
	} else {
		result.Details = append(result.Details, "Service is NOT enabled (will not start on boot)")
	}

	// CRITICAL: Get detailed service status
	statusCmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "consul", "--no-pager"},
		Capture: true,
	}

	statusOutput, _ := execute.Run(rc.Ctx, statusCmd)

	// Parse service state
	isActive := strings.Contains(statusOutput, "Active: active")
	isFailed := strings.Contains(statusOutput, "Active: failed")
	isInactive := strings.Contains(statusOutput, "Active: inactive")
	isActivating := strings.Contains(statusOutput, "Active: activating")

	if isActive {
		result.Details = append(result.Details, "Service Status: ACTIVE (running)")

		// Get MainPID
		for _, line := range strings.Split(statusOutput, "\n") {
			if strings.Contains(line, "Main PID:") {
				result.Details = append(result.Details, "  "+strings.TrimSpace(line))
			}
			if strings.Contains(line, "Tasks:") {
				result.Details = append(result.Details, "  "+strings.TrimSpace(line))
			}
			if strings.Contains(line, "Memory:") {
				result.Details = append(result.Details, "  "+strings.TrimSpace(line))
			}
		}
	} else if isFailed {
		result.Success = false
		result.Message = "Service is in FAILED state"
		result.Details = append(result.Details, "Service Status: FAILED")

		// Extract failure reason
		for _, line := range strings.Split(statusOutput, "\n") {
			if strings.Contains(line, "Process:") || strings.Contains(line, "code=") {
				result.Details = append(result.Details, "  "+strings.TrimSpace(line))
			}
		}
	} else if isInactive {
		result.Details = append(result.Details, "Service Status: INACTIVE (not running)")
	} else if isActivating {
		result.Details = append(result.Details, "Service Status: ACTIVATING (starting up)")
	} else {
		result.Details = append(result.Details, "Service Status: UNKNOWN")
	}

	// Check for recent restarts/crashes
	showCmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"show", "consul", "--property=NRestarts"},
		Capture: true,
	}

	if showOutput, err := execute.Run(rc.Ctx, showCmd); err == nil {
		restarts := strings.TrimSpace(strings.TrimPrefix(showOutput, "NRestarts="))
		if restarts != "0" && restarts != "" {
			result.Details = append(result.Details, "WARNING: Service has restarted "+restarts+" times")
			if !result.Success {
				result.Message = "Service has crashed/restarted " + restarts + " times"
			}
		}
	}

	if result.Success {
		result.Message = "Systemd service configuration is valid"
	}

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
		"bind: address already in use":    "Port binding conflict detected",
		"permission denied":                "Permission issues detected",
		"no such file or directory":        "Missing files or directories",
		"signal: killed":                   "Process was killed (likely timeout)",
		"failed to join":                   "Cluster join issues",
		"error getting server health":      "Health check failures",
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
		for _, issue := range foundIssues {
			result.Details = append(result.Details, "• "+issue)
		}
	} else {
		result.Message = "No critical issues found in recent logs"

		// Check if Consul started successfully at some point
		for _, line := range logLines {
			if strings.Contains(line, "Consul agent running!") ||
			   strings.Contains(line, "cluster leadership acquired") {
				result.Details = append(result.Details, "✓ Consul started successfully previously")
				break
			}
		}
	}

	return result
}

// checkConsulBinary verifies Consul binary exists and is executable
func checkConsulBinary(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Consul binary")

	result := DiagnosticResult{
		CheckName: "Consul Binary",
		Success:   true,
		Details:   []string{},
	}

	binaryPath := "/usr/bin/consul"

	// Check if binary exists
	info, err := os.Stat(binaryPath)
	if os.IsNotExist(err) {
		// Try alternate location
		binaryPath = "/usr/local/bin/consul"
		info, err = os.Stat(binaryPath)
		if err != nil {
			result.Success = false
			result.Message = "Consul binary not found"
			result.Details = append(result.Details, "Checked: /usr/bin/consul and /usr/local/bin/consul")
			return result
		}
	}

	result.Details = append(result.Details, fmt.Sprintf("Binary found at: %s", binaryPath))

	// Check if executable
	mode := info.Mode()
	if mode&0111 == 0 {
		result.Success = false
		result.Message = "Binary is not executable"
		result.Details = append(result.Details, fmt.Sprintf("Permissions: %s", mode))
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("Permissions: %s", mode))

	// Check version
	cmd := execute.Options{
		Command: binaryPath,
		Args:    []string{"version"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Success = false
		result.Message = "Could not get Consul version"
		result.Details = append(result.Details, output)
	} else {
		result.Message = "Binary is valid and executable"
		result.Details = append(result.Details, "Version: "+strings.TrimSpace(output))
	}

	return result
}

// checkConsulPermissions verifies file and directory permissions
func checkConsulPermissions(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking file permissions")

	result := DiagnosticResult{
		CheckName: "File Permissions",
		Success:   true,
		Details:   []string{},
	}

	paths := map[string]string{
		"/etc/consul.d":   "config directory",
		"/var/lib/consul": "data directory",
		"/opt/consul":     "opt directory",
	}

	allGood := true
	for path, desc := range paths {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			result.Details = append(result.Details, fmt.Sprintf("✗ %s (%s): NOT FOUND", desc, path))
			if desc == "config directory" || desc == "data directory" {
				allGood = false
			}
			continue
		}

		result.Details = append(result.Details,
			fmt.Sprintf("✓ %s (%s): exists, mode=%s", desc, path, info.Mode()))
	}

	if allGood {
		result.Message = "All required directories exist with proper permissions"
	} else {
		result.Success = false
		result.Message = "Some critical directories are missing"
	}

	return result
}

// checkConsulNetwork verifies network configuration
func checkConsulNetwork(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking network configuration")

	result := DiagnosticResult{
		CheckName: "Network Configuration",
		Success:   true,
		Details:   []string{},
	}

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		result.Success = false
		result.Message = "Failed to get network interfaces"
		return result
	}

	hasValidInterface := false
	for _, iface := range ifaces {
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Skip interfaces that are down
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Skip IPv6 and loopback
			if ipNet.IP.To4() == nil || ipNet.IP.IsLoopback() {
				continue
			}

			hasValidInterface = true
			result.Details = append(result.Details,
				fmt.Sprintf("Interface: %s, IP: %s", iface.Name, ipNet.IP.String()))
		}
	}

	if !hasValidInterface {
		result.Success = false
		result.Message = "No valid network interface found"
	} else {
		result.Message = "Network interface configured correctly"
	}

	return result
}

// checkConsulPorts performs comprehensive port connectivity checks
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
		addr := fmt.Sprintf("127.0.0.1:%d", port)
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
		apiURL := fmt.Sprintf("http://127.0.0.1:%d/v1/agent/self", shared.PortConsul)
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