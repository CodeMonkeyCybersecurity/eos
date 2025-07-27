// pkg/bootstrap/enhanced_errors.go
//
// Enhanced error reporting system that provides detailed context about
// what processes are using ports and actionable error messages.

package bootstrap

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnhancedError provides detailed error information with actionable suggestions
type EnhancedError struct {
	Type        ErrorType
	Message     string
	Details     []string
	Suggestions []string
	Processes   []ProcessInfo
	Context     map[string]string
}

// ErrorType categorizes different types of bootstrap errors
type ErrorType string

const (
	ErrorTypePortConflict      ErrorType = "port_conflict"
	ErrorTypeServiceConflict   ErrorType = "service_conflict"
	ErrorTypePermissionDenied  ErrorType = "permission_denied"
	ErrorTypeResourceShortage  ErrorType = "resource_shortage"
	ErrorTypeNetworkIssue      ErrorType = "network_issue"
	ErrorTypeConfigurationIssue ErrorType = "configuration_issue"
	ErrorTypeSystemRequirement ErrorType = "system_requirement"
)

// ProcessInfo contains detailed information about a process
type ProcessInfo struct {
	PID         int
	Name        string
	Command     string
	User        string
	StartTime   string
	Port        int
	ServiceName string
	CanStop     bool
	IsEosService bool
}

// Error implements the error interface
func (e *EnhancedError) Error() string {
	return e.Message
}

// EnhancePortError creates an enhanced error for port conflicts
func EnhancePortError(rc *eos_io.RuntimeContext, port int, originalErr error) *EnhancedError {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Enhancing port error", zap.Int("port", port))

	processInfo := getDetailedProcessInfo(rc, port)
	
	enhanced := &EnhancedError{
		Type:    ErrorTypePortConflict,
		Message: fmt.Sprintf("Port %d is already in use", port),
		Details: []string{
			fmt.Sprintf("Port %d is required for bootstrap but is currently occupied", port),
		},
		Processes: []ProcessInfo{processInfo},
		Context: map[string]string{
			"port":         strconv.Itoa(port),
			"service_name": getServiceNameForPort(port),
		},
	}

	// Add specific details about the process
	if processInfo.PID > 0 {
		enhanced.Details = append(enhanced.Details,
			fmt.Sprintf("Process: %s (PID %d)", processInfo.Name, processInfo.PID),
			fmt.Sprintf("User: %s", processInfo.User),
			fmt.Sprintf("Started: %s", processInfo.StartTime),
		)

		if processInfo.Command != "" {
			enhanced.Details = append(enhanced.Details,
				fmt.Sprintf("Command: %s", processInfo.Command))
		}
	}

	// Generate actionable suggestions
	enhanced.Suggestions = generatePortConflictSuggestions(processInfo, port)

	return enhanced
}

// EnhanceServiceError creates an enhanced error for service conflicts
func EnhanceServiceError(rc *eos_io.RuntimeContext, serviceName string, originalErr error) *EnhancedError {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Enhancing service error", zap.String("service", serviceName))

	enhanced := &EnhancedError{
		Type:    ErrorTypeServiceConflict,
		Message: fmt.Sprintf("Service conflict with %s", serviceName),
		Context: map[string]string{
			"service_name": serviceName,
		},
	}

	// Get service status and details
	serviceStatus := getServiceStatusInfo(rc, serviceName)
	if serviceStatus != nil {
		enhanced.Details = append(enhanced.Details,
			fmt.Sprintf("Service %s is currently %s", serviceName, serviceStatus.Status),
		)

		if serviceStatus.PID > 0 {
			processInfo := getProcessInfoByPID(rc, serviceStatus.PID)
			enhanced.Processes = append(enhanced.Processes, processInfo)
		}
	}

	// Generate suggestions
	enhanced.Suggestions = generateServiceConflictSuggestions(rc, serviceName, serviceStatus)

	return enhanced
}

// EnhancePermissionError creates an enhanced error for permission issues
func EnhancePermissionError(rc *eos_io.RuntimeContext, operation string, originalErr error) *EnhancedError {
	return &EnhancedError{
		Type:    ErrorTypePermissionDenied,
		Message: fmt.Sprintf("Permission denied for %s", operation),
		Details: []string{
			fmt.Sprintf("Operation '%s' requires elevated privileges", operation),
			"Bootstrap requires root access to configure system services",
		},
		Suggestions: []string{
			"Run the command with sudo:",
			fmt.Sprintf("  sudo eos bootstrap"),
			"",
			"Or if you're already using sudo, check that:",
			"• Your user is in the sudo group",
			"• The sudo session hasn't expired",
		},
		Context: map[string]string{
			"operation": operation,
			"required_permission": "root",
		},
	}
}

// EnhanceResourceError creates an enhanced error for resource shortages
func EnhanceResourceError(rc *eos_io.RuntimeContext, resourceType string, required, available interface{}) *EnhancedError {
	enhanced := &EnhancedError{
		Type:    ErrorTypeResourceShortage,
		Message: fmt.Sprintf("Insufficient %s", resourceType),
		Details: []string{
			fmt.Sprintf("Required %s: %v", resourceType, required),
			fmt.Sprintf("Available %s: %v", resourceType, available),
		},
		Context: map[string]string{
			"resource_type": resourceType,
		},
	}

	// Generate specific suggestions based on resource type
	switch resourceType {
	case "memory":
		enhanced.Suggestions = []string{
			"Free up memory by:",
			"• Stopping unnecessary services",
			"• Closing applications",
			"• Adding swap space if needed",
			"",
			"Or consider:",
			"• Using a machine with more RAM",
			"• Running EOS on a larger VM/instance",
		}
		
	case "disk":
		enhanced.Suggestions = []string{
			"Free up disk space by:",
			"• Removing unnecessary files: sudo apt-get autoremove",
			"• Cleaning package cache: sudo apt-get autoclean",
			"• Cleaning logs: sudo journalctl --vacuum-time=7d",
			"",
			"Or consider:",
			"• Expanding the disk/partition",
			"• Moving to a larger storage volume",
		}
		
	case "cpu":
		enhanced.Suggestions = []string{
			"This system has fewer CPU cores than recommended.",
			"EOS may still work but performance could be affected.",
			"",
			"To continue anyway:",
			"  eos bootstrap --force",
			"",
			"For better performance, consider:",
			"• Using a system with more CPU cores",
			"• Upgrading your VM/instance size",
		}
	}

	return enhanced
}

// getDetailedProcessInfo gets comprehensive information about the process using a port
func getDetailedProcessInfo(rc *eos_io.RuntimeContext, port int) ProcessInfo {
	logger := otelzap.Ctx(rc.Ctx)
	
	info := ProcessInfo{
		Port:        port,
		ServiceName: getServiceNameForPort(port),
	}

	// Use lsof to get detailed process information
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "lsof",
		Args:    []string{"-i", fmt.Sprintf(":%d", port), "-t"},
		Capture: true,
	})

	if err != nil {
		logger.Debug("lsof failed, trying ss", zap.Error(err))
		return getProcessInfoFromSS(rc, port)
	}

	pidStr := strings.TrimSpace(output)
	if pidStr == "" {
		return info
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return info
	}

	info.PID = pid
	
	// Get additional process details
	info = enrichProcessInfo(rc, info)
	
	return info
}

// getProcessInfoFromSS gets process info using ss command as fallback
func getProcessInfoFromSS(rc *eos_io.RuntimeContext, port int) ProcessInfo {
	info := ProcessInfo{
		Port:        port,
		ServiceName: getServiceNameForPort(port),
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp", fmt.Sprintf("sport = :%d", port)},
		Capture: true,
	})

	if err != nil {
		return info
	}

	// Parse ss output to extract PID
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf(":%d ", port)) {
			// Extract PID from users:(("process",pid=1234,fd=8))
			if pidStr := extractPIDFromSSOutput(line); pidStr != "" {
				if pid, err := strconv.Atoi(pidStr); err == nil {
					info.PID = pid
					info = enrichProcessInfo(rc, info)
				}
			}
			break
		}
	}

	return info
}

// extractPIDFromSSOutput extracts PID from ss command output
func extractPIDFromSSOutput(line string) string {
	// Look for pattern like pid=1234
	pidStart := strings.Index(line, "pid=")
	if pidStart == -1 {
		return ""
	}
	
	pidStart += 4 // Skip "pid="
	pidEnd := strings.Index(line[pidStart:], ",")
	if pidEnd == -1 {
		pidEnd = strings.Index(line[pidStart:], ")")
	}
	
	if pidEnd == -1 {
		return ""
	}
	
	return line[pidStart : pidStart+pidEnd]
}

// enrichProcessInfo adds additional details about a process
func enrichProcessInfo(rc *eos_io.RuntimeContext, info ProcessInfo) ProcessInfo {
	if info.PID == 0 {
		return info
	}

	// Get process name
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(info.PID), "-o", "comm="},
		Capture: true,
	}); err == nil {
		info.Name = strings.TrimSpace(output)
	}

	// Get full command
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(info.PID), "-o", "cmd="},
		Capture: true,
	}); err == nil {
		info.Command = strings.TrimSpace(output)
	}

	// Get user
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(info.PID), "-o", "user="},
		Capture: true,
	}); err == nil {
		info.User = strings.TrimSpace(output)
	}

	// Get start time
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(info.PID), "-o", "lstart="},
		Capture: true,
	}); err == nil {
		info.StartTime = strings.TrimSpace(output)
	}

	// Determine if it's an EOS service
	info.IsEosService = isEosServiceProcess(info.Name)

	// Determine if it can be stopped
	info.CanStop = canStopProcess(rc, info.Name, info.PID)

	return info
}

// getProcessInfoByPID gets process information by PID
func getProcessInfoByPID(rc *eos_io.RuntimeContext, pid int) ProcessInfo {
	info := ProcessInfo{PID: pid}
	return enrichProcessInfo(rc, info)
}

// getServiceNameForPort maps ports to service names
func getServiceNameForPort(port int) string {
	portMap := map[int]string{
		4505: "salt-master",
		4506: "salt-master",
		8000: "salt-api",
		8200: "vault",
		8300: "consul",
		8301: "consul",
		8302: "consul",
		8500: "consul",
		8600: "consul",
		4646: "nomad",
		4647: "nomad",
		4648: "nomad",
	}

	if service, exists := portMap[port]; exists {
		return service
	}

	return "unknown"
}

// ServiceStatusInfo represents the status of a service
type ServiceStatusInfo struct {
	Name   string
	Status string
	PID    int
	Active bool
}

// getServiceStatusInfo gets the status of a systemd service
func getServiceStatusInfo(rc *eos_io.RuntimeContext, serviceName string) *ServiceStatusInfo {
	status := &ServiceStatusInfo{Name: serviceName}

	// Get service status
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
		Capture: true,
	})

	if err == nil {
		status.Status = strings.TrimSpace(output)
		status.Active = status.Status == "active"
	}

	// Get main PID if active
	if status.Active {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"show", serviceName, "--property=MainPID"},
			Capture: true,
		})

		if err == nil {
			// Parse MainPID=12345
			parts := strings.Split(strings.TrimSpace(output), "=")
			if len(parts) == 2 {
				if pid, err := strconv.Atoi(parts[1]); err == nil {
					status.PID = pid
				}
			}
		}
	}

	return status
}

// generatePortConflictSuggestions generates actionable suggestions for port conflicts
func generatePortConflictSuggestions(process ProcessInfo, port int) []string {
	suggestions := []string{}

	if process.PID == 0 {
		suggestions = append(suggestions,
			fmt.Sprintf("Port %d is in use but process details unavailable", port),
			"Try manually checking what's using the port:",
			fmt.Sprintf("  sudo lsof -i :%d", port),
			fmt.Sprintf("  sudo ss -tlnp sport = :%d", port),
		)
		return suggestions
	}

	serviceName := process.ServiceName
	if serviceName == "unknown" {
		serviceName = process.Name
	}

	if process.IsEosService {
		suggestions = append(suggestions,
			fmt.Sprintf("This appears to be an existing EOS %s service", serviceName),
			"You can:",
			"• Integrate with existing installation: eos bootstrap --continue",
			"• Restart fresh: eos bootstrap --clean",
			"• Check service status: systemctl status " + serviceName,
		)
	} else {
		suggestions = append(suggestions,
			fmt.Sprintf("Port %d is used by %s (not an EOS service)", port, serviceName),
		)

		if process.CanStop {
			suggestions = append(suggestions,
				"You can:",
				fmt.Sprintf("• Stop the service: sudo systemctl stop %s", serviceName),
				"• Let EOS handle it: eos bootstrap --stop-conflicting",
				fmt.Sprintf("• Force installation: eos bootstrap --force"),
			)
		} else {
			suggestions = append(suggestions,
				"This process cannot be automatically stopped.",
				"You may need to:",
				fmt.Sprintf("• Manually stop %s", serviceName),
				"• Use a different system for EOS",
				"• Configure EOS to use different ports (advanced)",
			)
		}
	}

	suggestions = append(suggestions,
		"",
		"For more information:",
		fmt.Sprintf("• Process details: ps -p %d -f", process.PID),
		fmt.Sprintf("• Service logs: journalctl -u %s", serviceName),
	)

	return suggestions
}

// generateServiceConflictSuggestions generates suggestions for service conflicts
func generateServiceConflictSuggestions(rc *eos_io.RuntimeContext, serviceName string, status *ServiceStatusInfo) []string {
	suggestions := []string{}

	if status == nil || !status.Active {
		suggestions = append(suggestions,
			fmt.Sprintf("Service %s is not running", serviceName),
			"This should not cause conflicts.",
			"If issues persist, try:",
			fmt.Sprintf("• Reset service: sudo systemctl reset-failed %s", serviceName),
			"• Check logs: journalctl -u " + serviceName,
		)
		return suggestions
	}

	// Check if it's EOS managed
	isEosManaged := isEosManaged(rc, serviceName)

	if isEosManaged {
		suggestions = append(suggestions,
			fmt.Sprintf("Service %s appears to be EOS-managed", serviceName),
			"You can:",
			"• Continue with existing installation",
			"• Verify service health: eos read service-status",
			fmt.Sprintf("• Restart service: sudo systemctl restart %s", serviceName),
		)
	} else {
		suggestions = append(suggestions,
			fmt.Sprintf("Service %s is running but not EOS-managed", serviceName),
			"You can:",
			fmt.Sprintf("• Stop the service: sudo systemctl stop %s", serviceName),
			"• Backup configuration and reinstall",
			"• Force EOS installation: eos bootstrap --force",
		)
	}

	return suggestions
}

// PrintEnhancedError prints a formatted enhanced error with all details
func PrintEnhancedError(rc *eos_io.RuntimeContext, err *EnhancedError) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Error("╔══════════════════════════════════════╗")
	logger.Error("║             Error Details            ║")
	logger.Error("╚══════════════════════════════════════╝")
	
	logger.Error("Error: " + err.Message)
	logger.Error("Type: " + string(err.Type))
	
	if len(err.Details) > 0 {
		logger.Error("")
		logger.Error("Details:")
		for _, detail := range err.Details {
			logger.Error("  " + detail)
		}
	}

	if len(err.Processes) > 0 {
		logger.Error("")
		logger.Error("Process Information:")
		for _, proc := range err.Processes {
			logger.Error(fmt.Sprintf("  • %s (PID %d)", proc.Name, proc.PID))
			if proc.User != "" {
				logger.Error(fmt.Sprintf("    User: %s", proc.User))
			}
			if proc.StartTime != "" {
				logger.Error(fmt.Sprintf("    Started: %s", proc.StartTime))
			}
			if proc.Port > 0 {
				logger.Error(fmt.Sprintf("    Port: %d", proc.Port))
			}
		}
	}

	if len(err.Suggestions) > 0 {
		logger.Info("")
		logger.Info("Suggested Solutions:")
		for _, suggestion := range err.Suggestions {
			if suggestion == "" {
				logger.Info("")
			} else {
				logger.Info("  " + suggestion)
			}
		}
	}

	logger.Error("")
}