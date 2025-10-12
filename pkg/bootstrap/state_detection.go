// pkg/bootstrap/state_detection.go
//
// Intelligent bootstrap state detection system that can identify existing
// services, detect partial installations, and provide smart conflict resolution.

package bootstrap

import (
	"crypto/tls"
	"fmt"
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

// BootstrapState represents the current state of bootstrap components
type BootstrapState struct {
	Phase            BootstrapPhaseState
	Components       map[string]*ComponentStatus
	PortConflicts    []PortConflict
	CanReuseServices bool
	IsEosInstall     bool
	Recommendations  []string
}

// BootstrapPhaseState represents the overall bootstrap phase
type BootstrapPhaseState string

const (
	PhaseNotInstalled       BootstrapPhaseState = "not_installed"
	PhasePartiallyInstalled BootstrapPhaseState = "partially_installed"
	PhaseFullyInstalled     BootstrapPhaseState = "fully_installed"
	PhaseConflicting        BootstrapPhaseState = "conflicting"
	PhaseIncompatible       BootstrapPhaseState = "incompatible"
)

// ComponentStatus represents the status of a single service component
type ComponentStatus struct {
	Name         string
	Installed    bool
	Running      bool
	Healthy      bool
	Version      string
	Port         int
	ProcessID    int
	ProcessName  string
	ConfigPath   string
	IsEosManaged bool
	CanReuse     bool
	Issues       []string
}

// PortConflict represents a port that's already in use
type PortConflict struct {
	Port         int
	ServiceName  string
	ProcessID    int
	ProcessName  string
	CanStop      bool
	IsEosService bool
}

// ServiceHealthResponse represents a health check response
type ServiceHealthResponse struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	EosID   string `json:"eos_id,omitempty"`
}

// getRequiredPorts returns the list of ports required for bootstrap
func getRequiredPorts() []int {
	return []int{
		8200,                         // Vault
		8300, 8301, 8302, 8500, 8600, // Consul
		4646, 4647, 4648, // Nomad
	}
}

// DetectBootstrapState performs comprehensive bootstrap state detection
func DetectBootstrapState(rc *eos_io.RuntimeContext) (*BootstrapState, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Detecting bootstrap state")
	logger.Debug("Starting comprehensive state detection")

	state := &BootstrapState{
		Components:      make(map[string]*ComponentStatus),
		PortConflicts:   []PortConflict{},
		Recommendations: []string{},
	}

	// Check for existing Eos installation markers
	state.IsEosInstall = detectEosInstallation(rc)

	// Use the new service manager for better detection
	sm := NewServiceManager(rc)
	detectedServices, err := sm.DetectServices()
	if err != nil {
		logger.Warn("Service manager detection failed, using fallback", zap.Error(err))
		// Fallback to old method
		services := []string{"-master", "-api", "vault", "consul", "nomad"}
		for _, service := range services {
			status := detectComponentStatus(rc, service)
			state.Components[service] = status
		}
	} else {
		// Convert detected services to component status
		logger.Debug("Detected services", zap.Int("count", len(detectedServices)))
		for _, service := range detectedServices {
			logger.Debug("Processing detected service",
				zap.String("name", service.Name),
				zap.String("process_name", service.ProcessName),
				zap.String("process_path", service.ProcessPath),
				zap.String("status", service.Status),
				zap.Int("pid", service.PID),
				zap.Ints("ports", service.Ports))
			status := convertServiceToComponentStatus(service)
			state.Components[service.Name] = status
		}
	}

	// Check for port conflicts using the service manager
	requiredPorts := getRequiredPorts()
	for _, port := range requiredPorts {
		if conflict := checkPortConflictEnhanced(rc, sm, port); conflict != nil {
			state.PortConflicts = append(state.PortConflicts, *conflict)
		}
	}

	// Determine overall phase
	state.Phase = determineBootstrapPhase(state)

	// Determine if services can be reused
	state.CanReuseServices = canReuseExistingServices(state)

	// Generate recommendations
	state.Recommendations = generateRecommendations(state)

	logger.Info("Bootstrap state detection completed",
		zap.String("phase", string(state.Phase)),
		zap.Bool("is_eos_install", state.IsEosInstall),
		zap.Bool("can_reuse_services", state.CanReuseServices),
		zap.Int("port_conflicts", len(state.PortConflicts)))

	return state, nil
}

// detectEosInstallation checks for Eos installation markers
func detectEosInstallation(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)

	// Check for Eos configuration files
	eosMarkers := []string{
		"/opt/eos/.bootstrapped",
		"/etc/eos/config.yaml",
		"/etc/eos/bootstrap.conf",
		"/var/lib/eos/bootstrapped",
	}

	for _, marker := range eosMarkers {
		if _, err := os.Stat(marker); err == nil {
			logger.Debug("Found Eos installation marker", zap.String("marker", marker))
			return true
		}
	}

	// Check for Eos-specific configurations in services
	if hasEosConfiguration(rc) {
		return true
	}

	return false
}

// hasEosConfiguration checks if services have Eos-specific configurations
func hasEosConfiguration(rc *eos_io.RuntimeContext) bool {
	// Check  configuration for Eos-specific settings
	Config := "/etc//master"
	if data, err := os.ReadFile(Config); err == nil {
		content := string(data)
		if strings.Contains(content, "eos") || strings.Contains(content, "file_roots:") {
			return true
		}
	}

	// Check Consul for Eos metadata
	consulHealthURL := fmt.Sprintf("http://localhost:%d/v1/kv/eos/metadata", shared.PortConsul)
	// SECURITY: Add TLS configuration even for localhost connections
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	if resp, err := client.Get(consulHealthURL); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return true
		}
	}

	return false
}

// detectComponentStatus detects the status of a specific service component
func detectComponentStatus(rc *eos_io.RuntimeContext, serviceName string) *ComponentStatus {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Detecting component status", zap.String("service", serviceName))

	status := &ComponentStatus{
		Name:   serviceName,
		Issues: []string{},
	}

	// Check if service is installed
	status.Installed = isServiceInstalled(rc, serviceName)

	// Check if service is running
	if status.Installed {
		status.Running = isServiceRunning(rc, serviceName)

		// Get process information
		if status.Running {
			status.ProcessID, status.ProcessName = getServiceProcess(rc, serviceName)
		}

		// Check health
		status.Healthy = checkServiceHealth(rc, serviceName)

		// Get version
		status.Version = getServiceVersion(rc, serviceName)

		// Get port information
		status.Port = getServicePort(serviceName)

		// Check if Eos managed
		status.IsEosManaged = isEosManaged(rc, serviceName)

		// Determine if can reuse
		status.CanReuse = canReuseService(status)
	}

	return status
}

// isServiceInstalled checks if a service is installed
func isServiceInstalled(rc *eos_io.RuntimeContext, serviceName string) bool {
	// Check systemd unit file
	unitFile := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	if _, err := os.Stat(unitFile); err == nil {
		return true
	}

	// Check system package
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-l", serviceName},
		Capture: true,
	})

	return err == nil && strings.Contains(output, "ii")
}

// isServiceRunning checks if a service is currently running
func isServiceRunning(rc *eos_io.RuntimeContext, serviceName string) bool {
	active, err := SystemctlIsActive(rc, serviceName)
	return err == nil && active
}

// getServiceProcess gets process information for a running service
func getServiceProcess(rc *eos_io.RuntimeContext, serviceName string) (int, string) {
	pid, err := SystemctlGetMainPID(rc, serviceName)
	if err != nil {
		return 0, ""
	}

	// Get process name
	processName := getProcessName(rc, pid)
	return pid, processName
}

// getProcessName gets the process name for a given PID
func getProcessName(rc *eos_io.RuntimeContext, pid int) string {
	if pid == 0 {
		return ""
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"-p", strconv.Itoa(pid), "-o", "comm="},
		Capture: true,
	})

	if err != nil {
		return ""
	}

	return strings.TrimSpace(output)
}

// checkServiceHealth checks if a service is healthy
func checkServiceHealth(rc *eos_io.RuntimeContext, serviceName string) bool {
	switch serviceName {
	case "vault":
		return checkVaultHealthSimple(rc)
	case "consul":
		return checkConsulHealthSimple(rc)
	case "nomad":
		return checkNomadHealthSimple(rc)
	case "-api":
		// Migrated to HashiCorp stack - check Consul health instead
		return checkConsulHealthSimple(rc)
	default:
		// For unknown services, assume healthy if running
		return isServiceRunning(rc, serviceName)
	}
}

// checkVaultHealthSimple checks Vault health endpoint (simple version)
func checkVaultHealthSimple(rc *eos_io.RuntimeContext) bool {
	// SECURITY: Add TLS configuration
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/v1/sys/health", shared.PortVault))
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == 200 || resp.StatusCode == 429 // 429 = sealed but running
}

// checkConsulHealthSimple checks Consul health endpoint (simple version)
func checkConsulHealthSimple(rc *eos_io.RuntimeContext) bool {
	// SECURITY: Add TLS configuration
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/v1/status/leader", shared.PortConsul))
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == 200
}

// checkNomadHealthSimple checks Nomad health endpoint (simple version)
func checkNomadHealthSimple(rc *eos_io.RuntimeContext) bool {
	// SECURITY: Add TLS configuration
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	resp, err := client.Get("http://localhost:4646/v1/status/leader")
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == 200
}

// getServiceVersion gets the version of a service
func getServiceVersion(rc *eos_io.RuntimeContext, serviceName string) string {
	switch serviceName {
	case "vault":
		return getVaultVersion(rc)
	case "consul":
		return getConsulVersion(rc)
	case "nomad":
		return getNomadVersion(rc)

	default:
		return ""
	}
}

// getVaultVersion gets Vault version
func getVaultVersion(rc *eos_io.RuntimeContext) string {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"version"},
		Capture: true,
	})

	if err != nil {
		return ""
	}

	// Parse "Vault v1.13.1" format
	parts := strings.Fields(output)
	if len(parts) >= 2 {
		return strings.TrimPrefix(parts[1], "v")
	}

	return ""
}

// getConsulVersion gets Consul version
func getConsulVersion(rc *eos_io.RuntimeContext) string {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"version"},
		Capture: true,
	})

	if err != nil {
		return ""
	}

	// Parse first line
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			return strings.TrimPrefix(parts[1], "v")
		}
	}

	return ""
}

// getNomadVersion gets Nomad version
func getNomadVersion(rc *eos_io.RuntimeContext) string {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})

	if err != nil {
		return ""
	}

	// Parse first line
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			return strings.TrimPrefix(parts[1], "v")
		}
	}

	return ""
}

// getVersion gets  version
func getVersion(rc *eos_io.RuntimeContext) string {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "",
		Args:    []string{"--version"},
		Capture: true,
	})

	if err != nil {
		return ""
	}

	// Parse " 3004.2" format
	parts := strings.Fields(output)
	if len(parts) >= 2 {
		return parts[1]
	}

	return ""
}

// getServicePort gets the main port for a service
func getServicePort(serviceName string) int {
	portMap := map[string]int{
		"-master": 4505,
		"-api":    8000,
		"vault":   8200,
		"consul":  8500,
		"nomad":   4646,
	}

	return portMap[serviceName]
}

// isEosManaged checks if a service is managed by Eos
func isEosManaged(rc *eos_io.RuntimeContext, serviceName string) bool {
	// Check for Eos-specific configuration markers
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
		// Look for Eos-specific markers in configuration
		return strings.Contains(content, "# Generated by Eos") ||
			strings.Contains(content, "# Eos managed") ||
			strings.Contains(content, "eos_managed = true")
	}

	return false
}

// canReuseService determines if a service can be reused
func canReuseService(status *ComponentStatus) bool {
	if !status.Installed || !status.Running {
		return false
	}

	// If it's Eos managed and healthy, it can be reused
	if status.IsEosManaged && status.Healthy {
		return true
	}

	// If it's not Eos managed but healthy, it might be reusable with caution
	if status.Healthy && len(status.Issues) == 0 {
		return true
	}

	return false
}

// checkPortConflict checks if a port is in use and identifies the conflict
func checkPortConflict(rc *eos_io.RuntimeContext, port int) *PortConflict {
	// Use ss to check port usage
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp", fmt.Sprintf("sport = :%d", port)},
		Capture: true,
	})

	if err != nil || len(strings.TrimSpace(output)) <= 1 {
		return nil // Port is free
	}

	// Parse ss output to get process information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf(":%d ", port)) {
			// Port conflict detected - return basic conflict info
			return &PortConflict{
				Port:         port,
				ServiceName:  "unknown",
				ProcessID:    0,
				ProcessName:  "unknown",
				CanStop:      false,
				IsEosService: false,
			}
		}
	}

	// Generic conflict if we can't parse details
	return &PortConflict{
		Port:         port,
		ServiceName:  "unknown",
		ProcessID:    0,
		ProcessName:  "unknown",
		CanStop:      false,
		IsEosService: false,
	}
}

// parseSSOutput and mapProcessToService functions removed - were unused

// canStopProcess determines if a process can be safely stopped
func canStopProcess(rc *eos_io.RuntimeContext, processName string, processID int) bool {
	// Check if it's a system-critical process
	criticalProcesses := []string{"systemd", "kernel", "init"}
	for _, critical := range criticalProcesses {
		if strings.Contains(processName, critical) {
			return false
		}
	}

	// Check if we have permission to stop it (running as root/sudo)
	if os.Geteuid() != 0 {
		return false
	}

	// Check if it's managed by systemd
	if serviceName := getSystemdServiceByPID(rc, processID); serviceName != "" {
		return true
	}

	return true
}

// getSystemdServiceByPID gets the systemd service name for a PID
func getSystemdServiceByPID(rc *eos_io.RuntimeContext, pid int) string {
	output, err := SystemctlGetStatus(rc, strconv.Itoa(pid))
	if err != nil {
		return ""
	}

	// Parse systemctl status output for service name
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		firstLine := lines[0]
		// Format: "● vault.service - HashiCorp Vault"
		if strings.Contains(firstLine, ".service") {
			parts := strings.Fields(firstLine)
			if len(parts) >= 2 {
				return strings.TrimPrefix(parts[1], "●")
			}
		}
	}

	return ""
}

// isEosServiceProcess checks if a process belongs to an Eos service
func isEosServiceProcess(processName string) bool {
	eosServices := []string{"vault", "consul", "nomad", "-master", "-api"}
	for _, service := range eosServices {
		if processName == service {
			return true
		}
	}
	return false
}

// determineBootstrapPhase determines the overall bootstrap phase
func determineBootstrapPhase(state *BootstrapState) BootstrapPhaseState {
	installedCount := 0
	runningCount := 0
	healthyCount := 0
	totalServices := len(state.Components)

	for _, component := range state.Components {
		if component.Installed {
			installedCount++
		}
		if component.Running {
			runningCount++
		}
		if component.Healthy {
			healthyCount++
		}
	}

	// Check for conflicts
	if len(state.PortConflicts) > 0 && !state.CanReuseServices {
		return PhaseConflicting
	}

	// All services installed, running, and healthy
	if installedCount == totalServices && runningCount == totalServices && healthyCount == totalServices {
		return PhaseFullyInstalled
	}

	// Some services installed
	if installedCount > 0 {
		return PhasePartiallyInstalled
	}

	// Nothing installed
	return PhaseNotInstalled
}

// canReuseExistingServices determines if existing services can be reused
func canReuseExistingServices(state *BootstrapState) bool {
	if !state.IsEosInstall {
		return false
	}

	reusableCount := 0
	for _, component := range state.Components {
		if component.CanReuse {
			reusableCount++
		}
	}

	// If most services can be reused, then we can reuse the installation
	return reusableCount >= len(state.Components)/2
}

// generateRecommendations generates recommendations based on the detected state
func generateRecommendations(state *BootstrapState) []string {
	var recommendations []string

	switch state.Phase {
	case PhaseNotInstalled:
		recommendations = append(recommendations, "Fresh installation recommended")
		recommendations = append(recommendations, "Run: eos bootstrap")

	case PhasePartiallyInstalled:
		if state.CanReuseServices {
			recommendations = append(recommendations, "Continue existing installation")
			recommendations = append(recommendations, "Run: eos bootstrap --continue")
		} else {
			recommendations = append(recommendations, "Clean installation recommended")
			recommendations = append(recommendations, "Run: eos bootstrap --clean")
		}

	case PhaseFullyInstalled:
		if state.CanReuseServices {
			recommendations = append(recommendations, "System appears fully bootstrapped")
			recommendations = append(recommendations, "Run: eos bootstrap --verify")
		} else {
			recommendations = append(recommendations, "Reconfiguration may be needed")
			recommendations = append(recommendations, "Run: eos bootstrap --reconfigure")
		}

	case PhaseConflicting:
		recommendations = append(recommendations, "Port conflicts detected")
		if len(state.PortConflicts) > 0 {
			stoppableServices := []string{}
			for _, conflict := range state.PortConflicts {
				if conflict.CanStop && !conflict.IsEosService {
					stoppableServices = append(stoppableServices, conflict.ServiceName)
				}
			}
			if len(stoppableServices) > 0 {
				recommendations = append(recommendations,
					fmt.Sprintf("Stop conflicting services: %s", strings.Join(stoppableServices, ", ")))
				recommendations = append(recommendations, "Run: eos bootstrap --stop-conflicting")
			}
		}

	case PhaseIncompatible:
		recommendations = append(recommendations, "System incompatible with Eos")
		recommendations = append(recommendations, "Manual intervention required")
	}

	return recommendations
}

// PrintBootstrapStateReport prints a formatted report of the bootstrap state
func PrintBootstrapStateReport(rc *eos_io.RuntimeContext, state *BootstrapState) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("╔══════════════════════════════════════╗")
	logger.Info("║      Bootstrap State Detection       ║")
	logger.Info("╚══════════════════════════════════════╝")

	// Overall state
	logger.Info("Overall State:", zap.String("phase", string(state.Phase)))
	if state.IsEosInstall {
		logger.Info("✓ Eos installation detected")
	} else {
		logger.Info("No Eos installation markers found")
	}

	// Service status
	logger.Info("\nService Status:")
	for name, component := range state.Components {
		status := "❌"
		if component.Installed && component.Running && component.Healthy {
			status = ""
		} else if component.Installed && component.Running {
			status = ""
		} else if component.Installed {
			status = "🔴"
		}

		details := fmt.Sprintf("%s %s", status, name)
		if component.Version != "" {
			details += fmt.Sprintf(" (v%s)", component.Version)
		}
		if component.Port > 0 {
			details += fmt.Sprintf(" ::%d", component.Port)
		}
		if component.IsEosManaged {
			details += " [EOS]"
		}

		logger.Info(details)
	}

	// Port conflicts
	if len(state.PortConflicts) > 0 {
		logger.Info("\nPort Conflicts:")
		for _, conflict := range state.PortConflicts {
			status := "🔴"
			if conflict.IsEosService {
				status = ""
			}

			details := fmt.Sprintf("%s Port %d: %s (PID %d)",
				status, conflict.Port, conflict.ServiceName, conflict.ProcessID)
			if conflict.CanStop {
				details += " [Can Stop]"
			}
			logger.Info(details)
		}
	}

	// Recommendations
	if len(state.Recommendations) > 0 {
		logger.Info("\nRecommendations:")
		for _, rec := range state.Recommendations {
			logger.Info("→ " + rec)
		}
	}
}

// convertServiceToComponentStatus converts a Service to ComponentStatus
func convertServiceToComponentStatus(service Service) *ComponentStatus {
	return &ComponentStatus{
		Name:         service.Name,
		Installed:    service.Status != "not-found",
		Running:      service.Status == "active",
		Healthy:      service.Status == "active", // Simplified health check
		Version:      service.Version,
		Port:         getMainPort(service.Ports),
		ProcessID:    service.PID,
		ProcessName:  service.ProcessName,
		ConfigPath:   getConfigPath(service.Name),
		IsEosManaged: service.Managed,
		CanReuse:     service.Managed && service.Status == "active",
		Issues:       []string{},
	}
}

// getMainPort gets the main port from a list of ports
func getMainPort(ports []int) int {
	if len(ports) > 0 {
		return ports[0]
	}
	return 0
}

// getConfigPath gets the config path for a service
func getConfigPath(serviceName string) string {
	configPaths := map[string]string{

		"vault":  "/etc/vault/vault.hcl",
		"consul": "/etc/consul/consul.hcl",
		"nomad":  "/etc/nomad/nomad.hcl",
	}

	if path, exists := configPaths[serviceName]; exists {
		return path
	}

	return ""
}

// checkPortConflictEnhanced uses the service manager for enhanced port conflict detection
func checkPortConflictEnhanced(rc *eos_io.RuntimeContext, sm *ServiceManager, port int) *PortConflict {
	logger := otelzap.Ctx(rc.Ctx)

	service := sm.getServiceFromPort(port)
	if service == nil {
		logger.Debug("Port is free", zap.Int("port", port))
		return nil // Port is free
	}

	logger.Debug("Port conflict detected",
		zap.Int("port", port),
		zap.String("service_name", service.Name),
		zap.String("process_name", service.ProcessName),
		zap.String("process_path", service.ProcessPath),
		zap.Int("pid", service.PID),
		zap.Bool("can_stop", service.CanStop),
		zap.Bool("is_eos_managed", service.Managed))

	return &PortConflict{
		Port:         port,
		ServiceName:  service.Name,
		ProcessID:    service.PID,
		ProcessName:  service.ProcessName,
		CanStop:      service.CanStop,
		IsEosService: service.Managed,
	}
}
