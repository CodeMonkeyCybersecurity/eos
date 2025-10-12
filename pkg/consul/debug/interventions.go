package debug

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// killLingeringProcesses terminates any running consul processes
func killLingeringProcesses(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Killing lingering Consul processes")
	
	result := DiagnosticResult{
		CheckName:  "Process Cleanup",
		Success:    true,
		FixApplied: true,
		Details:    []string{},
	}
	
	// First try graceful termination
	cmd := execute.Options{
		Command: "pkill",
		Args:    []string{"-TERM", "-f", "consul"},
	}
	
	_, err := execute.Run(rc.Ctx, cmd)
	if err == nil {
		result.Details = append(result.Details, "Sent TERM signal to Consul processes")
		time.Sleep(2 * time.Second)
	}
	
	// Check if processes are still running
	checkCmd := execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "consul"},
		Capture: true,
	}
	
	output, err := execute.Run(rc.Ctx, checkCmd)
	if err == nil && output != "" {
		// Force kill if still running
		killCmd := execute.Options{
			Command: "pkill",
			Args:    []string{"-KILL", "-f", "consul"},
		}
		
		_, _ = execute.Run(rc.Ctx, killCmd)
		result.Details = append(result.Details, "Force killed remaining Consul processes")
	}
	
	// Verify all processes are gone
	time.Sleep(1 * time.Second)
	output, err = execute.Run(rc.Ctx, checkCmd)
	
	if err != nil || output == "" {
		result.Message = "Successfully cleaned up all Consul processes"
		result.FixMessage = "All Consul processes terminated"
	} else {
		result.Success = false
		result.Message = "Some Consul processes could not be terminated"
		result.FixMessage = "Failed to terminate all processes"
	}
	
	return result
}

// fixConfiguration attempts to fix common configuration issues
func fixConfiguration(rc *eos_io.RuntimeContext, configResult DiagnosticResult) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Applying configuration fixes")
	
	result := DiagnosticResult{
		CheckName:  "Configuration Fix",
		Success:    true,
		FixApplied: true,
		Details:    []string{},
	}
	
	configPath := "/etc/consul.d/consul.hcl"
	
	// Read current configuration
	content, err := os.ReadFile(configPath)
	if err != nil {
		result.Success = false
		result.Message = "Failed to read configuration file"
		return result
	}
	
	original := string(content)
	modified := original
	fixCount := 0
	
	// Apply fixes based on detected issues
	for _, detail := range configResult.Details {
		if strings.Contains(detail, "bootstrap_expect") {
			// Remove bootstrap_expect if bootstrap = true exists
			if strings.Contains(modified, "bootstrap = true") {
				modified = strings.ReplaceAll(modified, "bootstrap_expect = 1\n", "")
				modified = strings.ReplaceAll(modified, "bootstrap_expect = 1", "")
				result.Details = append(result.Details, "Removed bootstrap_expect (keeping bootstrap = true)")
				fixCount++
			}
		}
		
		if strings.Contains(detail, "enable_script_checks") {
			// Replace with enable_local_script_checks
			modified = strings.ReplaceAll(modified, 
				"enable_script_checks = true",
				"enable_local_script_checks = true")
			result.Details = append(result.Details, "Changed to enable_local_script_checks")
			fixCount++
		}
		
		if strings.Contains(detail, "bind_addr") {
			// Add bind_addr if missing
			if !strings.Contains(modified, "bind_addr") {
				// Insert after datacenter line
				lines := strings.Split(modified, "\n")
				for i, line := range lines {
					if strings.Contains(line, "datacenter") {
						lines[i] = line + "\nbind_addr = \"0.0.0.0\""
						break
					}
				}
				modified = strings.Join(lines, "\n")
				result.Details = append(result.Details, "Added bind_addr = \"0.0.0.0\"")
				fixCount++
			}
		}
	}
	
	if fixCount > 0 {
		// Backup original
		backupPath := configPath + ".backup." + time.Now().Format("20060102-150405")
		if err := os.WriteFile(backupPath, []byte(original), 0644); err != nil {
			result.Success = false
			result.Message = "Failed to create backup"
			return result
		}
		result.Details = append(result.Details, "Created backup: "+backupPath)
		
		// Write modified configuration
		if err := os.WriteFile(configPath, []byte(modified), 0644); err != nil {
			result.Success = false
			result.Message = "Failed to write fixed configuration"
			return result
		}
		
		// Validate the new configuration
		validateCmd := execute.Options{
			Command: "/usr/local/bin/consul",
			Args:    []string{"validate", "/etc/consul.d/"},
			Capture: true,
		}
		
		output, err := execute.Run(rc.Ctx, validateCmd)
		if err != nil {
			// Restore backup
			_ = os.WriteFile(configPath, []byte(original), 0644)
			result.Success = false
			result.Message = "Fixed configuration failed validation, restored backup"
			result.Details = append(result.Details, "Validation error: "+output)
			return result
		}
		
		result.Message = fmt.Sprintf("Applied %d configuration fix(es)", fixCount)
		result.FixMessage = "Configuration issues resolved"
	} else {
		result.Message = "No configuration fixes needed"
		result.FixMessage = "Configuration already optimal"
	}
	
	return result
}

// testManualStart attempts to start Consul manually for better error visibility
func testManualStart(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Testing manual Consul start")
	
	result := DiagnosticResult{
		CheckName: "Manual Start Test",
		Success:   true,
		Details:   []string{},
	}
	
	// Create a context with timeout for the test
	testCtx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()
	
	// Run consul manually as consul user
	cmd := execute.Options{
		Command: "sudo",
		Args:    []string{"-u", "consul", "/usr/local/bin/consul", "agent", "-config-dir=/etc/consul.d/"},
		Capture: true,
		Timeout: 10000, // 10 seconds
	}
	
	output, err := execute.Run(testCtx, cmd)
	
	if err != nil {
		result.Success = false
		
		// Check if it was a timeout
		if strings.Contains(err.Error(), "context deadline exceeded") {
			result.Message = "Manual start timed out after 10 seconds (this might be normal)"
			result.Details = append(result.Details, "Consul may be starting slowly")
		} else {
			result.Message = "Manual start failed with error"
			result.Details = append(result.Details, err.Error())
		}
		
		// Include any output we got
		if output != "" {
			outputLines := strings.Split(output, "\n")
			for i, line := range outputLines {
				if i < 20 { // Limit output
					result.Details = append(result.Details, line)
				}
			}
		}
		
		// Look for specific error patterns
		if strings.Contains(output, "bind: address already in use") {
			result.Details = append(result.Details, "→ Port conflict detected - stop conflicting service first")
		}
		if strings.Contains(output, "permission denied") {
			result.Details = append(result.Details, "→ Permission issue - check file ownership")
		}
	} else {
		result.Message = "Manual start initiated successfully"
		result.Details = append(result.Details, "Consul started without immediate errors")
		result.Details = append(result.Details, "Check 'ps aux | grep consul' to verify it's running")
	}
	
	return result
}

// testMinimalConfiguration creates and tests a minimal Consul configuration
func testMinimalConfiguration(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Testing with minimal configuration")
	
	result := DiagnosticResult{
		CheckName:  "Minimal Config Test",
		Success:    true,
		FixApplied: true,
		Details:    []string{},
	}
	
	// Backup current config
	currentConfig := "/etc/consul.d/consul.hcl"
	backupPath := currentConfig + ".debug-backup"
	
	if _, err := os.Stat(currentConfig); err == nil {
		content, _ := os.ReadFile(currentConfig)
		_ = os.WriteFile(backupPath, content, 0644)
		result.Details = append(result.Details, "Backed up current config to: "+backupPath)
	}
	
	// Create minimal configuration
	minimalConfig := fmt.Sprintf(`datacenter = "dc1"
data_dir = "/opt/consul"
log_level = "DEBUG"
node_name = "consul-debug-test"
server = true
bootstrap = true
ui_config {
  enabled = true
}
addresses {
  http = "0.0.0.0"
}
ports {
  http = %d
}
`, shared.PortConsul)
	
	minimalPath := "/etc/consul.d/consul-minimal.hcl"
	if err := os.WriteFile(minimalPath, []byte(minimalConfig), 0644); err != nil {
		result.Success = false
		result.Message = "Failed to create minimal configuration"
		return result
	}
	
	result.Details = append(result.Details, "Created minimal config at: "+minimalPath)
	
	// Test with minimal config
	testCtx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()
	
	cmd := execute.Options{
		Command: "sudo",
		Args:    []string{"-u", "consul", "/usr/local/bin/consul", "agent", "-config-file=" + minimalPath},
		Capture: true,
		Timeout: 10000,
	}
	
	output, err := execute.Run(testCtx, cmd)
	
	if err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		result.Success = false
		result.Message = "Minimal configuration test failed"
		result.Details = append(result.Details, "Error: "+err.Error())
		if output != "" {
			result.Details = append(result.Details, "Output: "+output)
		}
	} else {
		result.Message = "Minimal configuration test passed"
		result.Details = append(result.Details, "Consul can start with minimal config")
		result.Details = append(result.Details, "Issue is likely in the main configuration")
		result.FixMessage = "Consider using minimal config as starting point"
	}
	
	// Clean up
	_ = os.Remove(minimalPath)
	
	return result
}