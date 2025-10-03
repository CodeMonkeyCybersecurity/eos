// pkg/bootstrap/service_manager.go
//
// Robust service management abstraction that properly handles
// process detection, service name mapping, and service operations.

package bootstrap

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceManager provides robust service management capabilities
type ServiceManager struct {
	rc *eos_io.RuntimeContext
}

// NewServiceManager creates a new service manager
func NewServiceManager(rc *eos_io.RuntimeContext) *ServiceManager {
	return &ServiceManager{rc: rc}
}

// Service represents a system service with all its details
type Service struct {
	Name        string // Actual systemd service name
	DisplayName string // Human-readable name
	Version     string // Service version
	Status      string // Current status (active, inactive, failed, etc.)
	Ports       []int  // Ports used by this service
	PID         int    // Main process PID
	ProcessName string // Process name from ss/lsof
	ProcessPath string // Full process path
	Managed     bool   // Is this managed by EOS?
	CanStop     bool   // Can this service be safely stopped?
	StartTime   string // When the service started
	User        string // User running the service
}

// ProcessToServiceMapping maps various process names/paths to systemd service names
var ProcessToServiceMapping = map[string]string{
	// Direct process names
	"-api":   "-api",
	"vault":  "vault",
	"consul": "consul",
	"nomad":  "nomad",

	"/opt/vault/":  "vault",
	"/opt/consul/": "consul",
	"/opt/nomad/":  "nomad",

	// Common variations - removed duplicate empty keys
	// These were causing compilation errors

	// Handle cases where full paths are returned
	"/usr/bin/-api":   "-api",
	"/usr/bin/vault":  "vault",
	"/usr/bin/consul": "consul",
	"/usr/bin/nomad":  "nomad",
}

// ServicePortMapping maps ports to expected service names
var ServicePortMapping = map[int]string{

	8000: "-api",
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

// DetectServices detects all relevant services on the system
func (sm *ServiceManager) DetectServices() ([]Service, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Detecting services on system")

	services := []Service{}

	// Get all systemd services that might be relevant
	logger.Debug("Calling getSystemdServices()")
	systemdServices, err := sm.getSystemdServices()
	if err != nil {
		logger.Warn("Failed to get systemd services", zap.Error(err))
	} else {
		logger.Debug("getSystemdServices() completed", zap.Int("count", len(systemdServices)))
		services = append(services, systemdServices...)
	}

	// Get services detected by port usage
	logger.Debug("Calling getServicesFromPorts()")
	portServices, err := sm.getServicesFromPorts()
	if err != nil {
		logger.Warn("Failed to get services from ports", zap.Error(err))
	} else {
		logger.Debug("getServicesFromPorts() completed", zap.Int("count", len(portServices)))
		// Merge port-detected services with systemd services
		services = sm.mergeServices(services, portServices)
	}

	logger.Info("Service detection completed", zap.Int("total_services", len(services)))
	return services, nil
}

// getSystemdServices gets services from systemd
func (sm *ServiceManager) getSystemdServices() ([]Service, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)
	services := []Service{}

	// List of service names we care about
	serviceNames := []string{"-master", "-api", "vault", "consul", "nomad"}

	for _, serviceName := range serviceNames {
		service, err := sm.getSystemdServiceDetails(serviceName)
		if err != nil {
			logger.Debug("Service not found or error getting details",
				zap.String("service", serviceName),
				zap.Error(err))
			continue
		}

		if service != nil {
			services = append(services, *service)
		}
	}

	return services, nil
}

// getSystemdServiceDetails gets detailed information about a systemd service
func (sm *ServiceManager) getSystemdServiceDetails(serviceName string) (*Service, error) {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Check if service exists
	output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", serviceName + ".service"},
		Capture: true,
	})

	if err != nil || !strings.Contains(output, serviceName) {
		return nil, fmt.Errorf("service %s not found", serviceName)
	}

	service := &Service{
		Name:        serviceName,
		DisplayName: serviceName,
	}

	// Get service status
	output, err = execute.Run(sm.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
		Capture: true,
	})

	if err == nil {
		service.Status = strings.TrimSpace(output)
	} else {
		service.Status = "unknown"
	}

	// If service is active, get more details
	if service.Status == "active" {
		// Get PID
		output, err = execute.Run(sm.rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"show", serviceName, "--property=MainPID"},
			Capture: true,
		})

		if err == nil {
			parts := strings.Split(strings.TrimSpace(output), "=")
			if len(parts) == 2 {
				if pid, err := strconv.Atoi(parts[1]); err == nil && pid > 0 {
					service.PID = pid

					// Get process details
					sm.enrichServiceWithProcessDetails(service)
				}
			}
		}

		// Get service version
		service.Version = sm.getServiceVersion(serviceName)

		// Check if EOS managed
		service.Managed = sm.isEosManaged(serviceName)

		// Determine ports
		service.Ports = sm.getServicePorts(serviceName)
	}

	// Service can be stopped if we have root privileges
	service.CanStop = os.Geteuid() == 0

	logger.Debug("Service details retrieved",
		zap.String("service", serviceName),
		zap.String("status", service.Status),
		zap.Int("pid", service.PID))

	return service, nil
}

// enrichServiceWithProcessDetails adds process information to a service
func (sm *ServiceManager) enrichServiceWithProcessDetails(service *Service) {
	if service.PID == 0 {
		return
	}

	// Get process name
	if output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(service.PID), "-o", "comm="},
		Capture: true,
	}); err == nil {
		service.ProcessName = strings.TrimSpace(output)
	}

	// Get full command line
	if output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(service.PID), "-o", "cmd="},
		Capture: true,
	}); err == nil {
		service.ProcessPath = strings.TrimSpace(output)
	}

	// Get user
	if output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(service.PID), "-o", "user="},
		Capture: true,
	}); err == nil {
		service.User = strings.TrimSpace(output)
	}

	// Get start time
	if output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(service.PID), "-o", "lstart="},
		Capture: true,
	}); err == nil {
		service.StartTime = strings.TrimSpace(output)
	}
}

// getServicesFromPorts detects services by checking what's using required ports
func (sm *ServiceManager) getServicesFromPorts() ([]Service, error) {
	services := []Service{}

	requiredPorts := getRequiredPorts()

	for _, port := range requiredPorts {
		service := sm.getServiceFromPort(port)
		if service != nil {
			services = append(services, *service)
		}
	}

	return services, nil
}

// getServiceFromPort detects what service is using a specific port
func (sm *ServiceManager) getServiceFromPort(port int) *Service {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Debug("Checking what's using port", zap.Int("port", port))

	// Use ss to find what's using the port
	output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp", fmt.Sprintf("sport = :%d", port)},
		Capture: true,
	})

	if err != nil || len(strings.TrimSpace(output)) <= 1 {
		logger.Debug("Port not in use", zap.Int("port", port))
		return nil // Port not in use
	}

	logger.Debug("ss output for port",
		zap.Int("port", port),
		zap.String("output", output))

	// Parse ss output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf(":%d ", port)) {
			logger.Debug("Parsing ss line",
				zap.String("line", line),
				zap.Int("port", port))
			return sm.parseServiceFromSSLine(line, port)
		}
	}

	return nil
}

// parseServiceFromSSLine parses a line from ss output to extract service information
func (sm *ServiceManager) parseServiceFromSSLine(line string, port int) *Service {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Extract process info from users:((name,pid=123,fd=8))
	processName := ""
	pid := 0

	// Find the users part
	if userStart := strings.Index(line, "users:(("); userStart != -1 {
		usersPart := line[userStart:]

		// Extract process name
		if nameStart := strings.Index(usersPart, "((\""); nameStart != -1 {
			nameStart += 3
			if nameEnd := strings.Index(usersPart[nameStart:], "\","); nameEnd != -1 {
				processName = usersPart[nameStart : nameStart+nameEnd]
			}
		}

		// If we didn't find the process name with quotes, try without
		if processName == "" {
			// Try alternative parsing for format like users:((-master,pid=123,fd=8))
			if nameStart := strings.Index(usersPart, "(("); nameStart != -1 {
				nameStart += 2
				if nameEnd := strings.Index(usersPart[nameStart:], ","); nameEnd != -1 {
					processName = usersPart[nameStart : nameStart+nameEnd]
				}
			}
		}

		// Extract PID
		if pidStart := strings.Index(usersPart, "pid="); pidStart != -1 {
			pidStart += 4
			if pidEnd := strings.Index(usersPart[pidStart:], ","); pidEnd != -1 {
				if p, err := strconv.Atoi(usersPart[pidStart : pidStart+pidEnd]); err == nil {
					pid = p
				}
			} else if pidEnd := strings.Index(usersPart[pidStart:], ")"); pidEnd != -1 {
				// Handle case where pid is last item
				if p, err := strconv.Atoi(usersPart[pidStart : pidStart+pidEnd]); err == nil {
					pid = p
				}
			}
		}
	}

	if processName == "" && pid == 0 {
		logger.Debug("Could not extract process info from ss line",
			zap.String("line", line),
			zap.Int("port", port))
		return nil
	}

	// Map process name to service name
	serviceName := sm.mapProcessToServiceName(processName, port)

	logger.Debug("Parsed service from ss output",
		zap.String("process_name", processName),
		zap.String("mapped_service_name", serviceName),
		zap.Int("pid", pid),
		zap.Int("port", port))

	service := &Service{
		Name:        serviceName,
		DisplayName: serviceName,
		ProcessName: processName,
		PID:         pid,
		Ports:       []int{port},
		Status:      "active", // If it's using a port, it's probably active
		CanStop:     os.Geteuid() == 0,
	}

	// Enrich with more details
	sm.enrichServiceWithProcessDetails(service)

	// Get version
	service.Version = sm.getServiceVersion(serviceName)

	// Check if EOS managed
	service.Managed = sm.isEosManaged(serviceName)

	return service
}

// mapProcessToServiceName maps a process name to a systemd service name
func (sm *ServiceManager) mapProcessToServiceName(processName string, port int) string {
	logger := otelzap.Ctx(sm.rc.Ctx)

	// Clean up the process name first
	cleanProcessName := processName
	// Remove any trailing slashes
	cleanProcessName = strings.TrimSuffix(cleanProcessName, "/")
	// If it's a full path, extract just the executable name
	if strings.Contains(cleanProcessName, "/") {
		parts := strings.Split(cleanProcessName, "/")
		if len(parts) > 0 {
			lastPart := parts[len(parts)-1]
			if lastPart != "" {
				// Also check if the last part is a known service
				if _, exists := ProcessToServiceMapping[lastPart]; exists {
					cleanProcessName = lastPart
				}
			}
		}
	}

	// First try direct mapping from clean process name
	if serviceName, exists := ProcessToServiceMapping[cleanProcessName]; exists {
		logger.Debug("Mapped process to service by name",
			zap.String("process", processName),
			zap.String("clean_process", cleanProcessName),
			zap.String("service", serviceName))
		return serviceName
	}

	// Try partial matching for paths
	for pattern, serviceName := range ProcessToServiceMapping {
		// Check if the process name contains the pattern or if it's an exact match
		if strings.Contains(processName, pattern) || processName == pattern {
			logger.Debug("Mapped process to service by pattern",
				zap.String("process", processName),
				zap.String("pattern", pattern),
				zap.String("service", serviceName))
			return serviceName
		}
	}

	// Try mapping by port - this is very reliable for our known services
	if serviceName, exists := ServicePortMapping[port]; exists {
		logger.Debug("Mapped process to service by port",
			zap.String("process", processName),
			zap.Int("port", port),
			zap.String("service", serviceName))
		return serviceName
	}

	// If all else fails, try to guess from process name
	serviceName := sm.guessServiceName(processName)
	logger.Debug("Guessed service name",
		zap.String("process", processName),
		zap.String("guessed_service", serviceName))

	return serviceName
}

// guessServiceName attempts to guess the service name from process name
func (sm *ServiceManager) guessServiceName(processName string) string {
	// Handle common patterns
	if strings.Contains(processName, "") {
		if strings.Contains(processName, "api") {
			return "-api"
		}
		return "-master"
	}

	if strings.Contains(processName, "vault") {
		return "vault"
	}

	if strings.Contains(processName, "consul") {
		return "consul"
	}

	if strings.Contains(processName, "nomad") {
		return "nomad"
	}

	// Return the process name as-is if we can't guess
	return processName
}

// getServiceVersion gets the version of a service
func (sm *ServiceManager) getServiceVersion(serviceName string) string {
	switch serviceName {
	case "-master", "-api":
		return getVersion(sm.rc)
	case "vault":
		return getVaultVersion(sm.rc)
	case "consul":
		return getConsulVersion(sm.rc)
	case "nomad":
		return getNomadVersion(sm.rc)
	default:
		return ""
	}
}

// isEosManaged checks if a service is managed by EOS
func (sm *ServiceManager) isEosManaged(serviceName string) bool {
	configPaths := map[string]string{

		"vault":  "/etc/vault/vault.hcl",
		"consul": "/etc/consul/consul.hcl",
		"nomad":  "/etc/nomad/nomad.hcl",
	}

	configPath, exists := configPaths[serviceName]
	if !exists {
		return false
	}

	if data, err := os.ReadFile(configPath); err == nil {
		content := string(data)
		return strings.Contains(content, "# Generated by EOS") ||
			strings.Contains(content, "# EOS managed") ||
			strings.Contains(content, "eos_managed = true")
	}

	return false
}

// getServicePorts gets the ports used by a service
func (sm *ServiceManager) getServicePorts(serviceName string) []int {
	portMap := map[string][]int{
		"-master": {4505, 4506},
		"-api":    {8000},
		"vault":   {8200},
		"consul":  {8300, 8301, 8302, 8500, 8600},
		"nomad":   {4646, 4647, 4648},
	}

	if ports, exists := portMap[serviceName]; exists {
		return ports
	}

	return []int{}
}

// mergeServices merges two lists of services, avoiding duplicates
func (sm *ServiceManager) mergeServices(services1, services2 []Service) []Service {
	serviceMap := make(map[string]Service)

	// Add all services from first list
	for _, service := range services1 {
		serviceMap[service.Name] = service
	}

	// Add services from second list, merging information
	for _, service := range services2 {
		if existing, exists := serviceMap[service.Name]; exists {
			// Merge information
			merged := existing

			// Use more complete information
			if service.PID > 0 && existing.PID == 0 {
				merged.PID = service.PID
				merged.ProcessName = service.ProcessName
				merged.ProcessPath = service.ProcessPath
				merged.User = service.User
				merged.StartTime = service.StartTime
			}

			// Merge ports
			portMap := make(map[int]bool)
			for _, port := range existing.Ports {
				portMap[port] = true
			}
			for _, port := range service.Ports {
				if !portMap[port] {
					merged.Ports = append(merged.Ports, port)
				}
			}

			serviceMap[service.Name] = merged
		} else {
			serviceMap[service.Name] = service
		}
	}

	// Convert back to slice
	result := []Service{}
	for _, service := range serviceMap {
		result = append(result, service)
	}

	return result
}

// StopService stops a service using the most appropriate method
func (sm *ServiceManager) StopService(service Service) error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Stopping service",
		zap.String("service_name", service.Name),
		zap.String("process_name", service.ProcessName),
		zap.String("process_path", service.ProcessPath),
		zap.Int("pid", service.PID))

	// Strategy 1: Try systemd service stop
	logger.Debug("Attempting systemctl stop", zap.String("service", service.Name))
	output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", service.Name},
		Capture: true,
	})

	if err == nil {
		logger.Info("Service stopped successfully via systemctl", zap.String("service", service.Name))
		return nil
	}

	logger.Warn("systemctl stop failed, trying alternatives",
		zap.String("service", service.Name),
		zap.Error(err),
		zap.String("output", output))

	// Strategy 2: Try stopping with .service suffix
	if !strings.HasSuffix(service.Name, ".service") {
		output, err = execute.Run(sm.rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", service.Name + ".service"},
			Capture: true,
		})

		if err == nil {
			logger.Info("Service stopped successfully via systemctl with .service suffix",
				zap.String("service", service.Name))
			return nil
		}
	}

	// Strategy 3: Kill by PID if we have it
	if service.PID > 0 {
		logger.Info("Attempting to stop service by PID",
			zap.String("service", service.Name),
			zap.Int("pid", service.PID))

		// Try graceful termination first
		output, err = execute.Run(sm.rc.Ctx, execute.Options{
			Command: "kill",
			Args:    []string{"-TERM", strconv.Itoa(service.PID)},
			Capture: true,
		})

		if err == nil {
			logger.Info("Service stopped successfully via SIGTERM",
				zap.String("service", service.Name),
				zap.Int("pid", service.PID))
			return nil
		}
	}

	return fmt.Errorf("failed to stop service %s using all available methods", service.Name)
}

// StartService starts a service
func (sm *ServiceManager) StartService(service Service) error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Starting service", zap.String("service", service.Name))

	output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", service.Name},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to start service %s: %w (output: %s)", service.Name, err, output)
	}

	logger.Info("Service started successfully", zap.String("service", service.Name))
	return nil
}

// RestartService restarts a service
func (sm *ServiceManager) RestartService(service Service) error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Restarting service", zap.String("service", service.Name))

	output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", service.Name},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to restart service %s: %w (output: %s)", service.Name, err, output)
	}

	logger.Info("Service restarted successfully", zap.String("service", service.Name))
	return nil
}

// DiagnosePortConflict provides detailed diagnostic information about a port conflict
func (sm *ServiceManager) DiagnosePortConflict(port int) {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("🔍 Diagnosing port conflict", zap.Int("port", port))

	// Show what's using the port with lsof
	logger.Info("Process details from lsof:")
	if output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "lsof",
		Args:    []string{"-i", fmt.Sprintf(":%d", port)},
		Capture: true,
	}); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				logger.Info("  " + line)
			}
		}
	} else {
		logger.Warn("lsof failed", zap.Error(err))
	}

	// Show systemd services
	logger.Info("Related systemd services:")
	if output, err := execute.Run(sm.rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-units", "--type=service", "--state=running"},
		Capture: true,
	}); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "") || strings.Contains(line, "vault") ||
				strings.Contains(line, "consul") || strings.Contains(line, "nomad") {
				logger.Info("  " + strings.TrimSpace(line))
			}
		}
	}

	// Suggest manual fixes
	logger.Info("Manual fix commands:")
	logger.Info(fmt.Sprintf("  To kill by port: sudo lsof -ti:%d | xargs kill -9", port))

	if expectedService, exists := ServicePortMapping[port]; exists {
		logger.Info(fmt.Sprintf("  To stop expected service: sudo systemctl stop %s", expectedService))
	}
}
