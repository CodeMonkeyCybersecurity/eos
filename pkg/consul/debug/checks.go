package debug

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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
		return result
	}
	
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
			"Service uses Type=notify - may cause startup issues with some Consul versions")
	}
	
	if !strings.Contains(serviceStr, "TimeoutStartSec") {
		result.Details = append(result.Details,
			"No TimeoutStartSec specified - using systemd default (90s)")
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
		result.Details = append(result.Details, "Service is enabled")
	} else {
		result.Details = append(result.Details, "Service is not enabled")
	}
	
	result.Message = "Systemd service configuration checked"
	
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