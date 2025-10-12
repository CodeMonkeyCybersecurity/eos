// pkg/bootstrap/validation.go
//
// Validation utilities for bootstrap prerequisites and system requirements

package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemRequirements defines minimum system requirements
type SystemRequirements struct {
	MinCPUCores   int
	MinMemoryGB   int
	MinDiskGB     int
	RequiredPorts []int
	RequiredOS    string
	MinOSVersion  string
}

// DefaultSystemRequirements returns minimum requirements for bootstrap
func DefaultSystemRequirements() SystemRequirements {
	return SystemRequirements{
		MinCPUCores:   2,
		MinMemoryGB:   4,
		MinDiskGB:     20,
		RequiredPorts: []int{4505, 4506, 8200, 8300, 8301, 8302, 8500, 8600, 4646, 4647, 4648},
		RequiredOS:    "ubuntu",
		MinOSVersion:  "20.04",
	}
}

// ValidationResult contains the results of system validation
type ValidationResult struct {
	Passed     bool
	Errors     []string
	Warnings   []string
	SystemInfo SystemInfo
}

// SystemInfo contains discovered system information
type SystemInfo struct {
	OS           string
	OSVersion    string
	Architecture string
	CPUCores     int
	MemoryGB     int
	DiskGB       int
	Hostname     string
	IsContainer  bool
	IsVM         bool
}

// ValidateSystem performs comprehensive system validation
func ValidateSystem(rc *eos_io.RuntimeContext, requirements SystemRequirements) (*ValidationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating system prerequisites")

	result := &ValidationResult{
		Passed:   true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Gather system information
	sysInfo, err := gatherSystemInfo(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to gather system information: %w", err)
	}
	result.SystemInfo = *sysInfo

	// Validate OS
	if err := validateOS(sysInfo, requirements); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Passed = false
	}

	// Validate resources
	if err := validateResources(sysInfo, requirements); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Passed = false
	}

	// Validate ports
	if err := validatePorts(rc, requirements.RequiredPorts); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Passed = false
	}

	// Check for conflicts
	conflicts := checkForConflicts(rc)
	if len(conflicts) > 0 {
		result.Warnings = append(result.Warnings, conflicts...)
	}

	// Check environment
	envWarnings := checkEnvironment(rc)
	if len(envWarnings) > 0 {
		result.Warnings = append(result.Warnings, envWarnings...)
	}

	logger.Info("System validation completed",
		zap.Bool("passed", result.Passed),
		zap.Int("errors", len(result.Errors)),
		zap.Int("warnings", len(result.Warnings)))

	return result, nil
}

// gatherSystemInfo collects system information
func gatherSystemInfo(rc *eos_io.RuntimeContext) (*SystemInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Gathering system information")

	info := &SystemInfo{
		Architecture: runtime.GOARCH,
	}

	// Get OS information
	if err := getOSInfo(rc, info); err != nil {
		return nil, fmt.Errorf("failed to get OS info: %w", err)
	}

	// Get CPU information
	if err := getCPUInfo(rc, info); err != nil {
		return nil, fmt.Errorf("failed to get CPU info: %w", err)
	}

	// Get memory information
	if err := getMemoryInfo(rc, info); err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	// Get disk information
	if err := getDiskInfo(rc, info); err != nil {
		return nil, fmt.Errorf("failed to get disk info: %w", err)
	}

	// Get hostname
	hostname, _ := os.Hostname()
	info.Hostname = hostname

	// Detect container/VM
	info.IsContainer = detectContainer()
	info.IsVM = detectVM(rc)

	logger.Debug("System information gathered",
		zap.String("os", info.OS),
		zap.String("version", info.OSVersion),
		zap.Int("cpu_cores", info.CPUCores),
		zap.Int("memory_gb", info.MemoryGB),
		zap.Int("disk_gb", info.DiskGB))

	return info, nil
}

// getOSInfo retrieves OS name and version
func getOSInfo(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	// Read /etc/os-release
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "cat",
		Args:    []string{"/etc/os-release"},
		Capture: true,
	})

	if err != nil {
		return err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			info.OS = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			info.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}

	return nil
}

// getCPUInfo retrieves CPU core count
func getCPUInfo(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nproc",
		Capture: true,
	})

	if err != nil {
		return err
	}

	_, _ = fmt.Sscanf(strings.TrimSpace(output), "%d", &info.CPUCores)
	return nil
}

// getMemoryInfo retrieves total memory in GB
func getMemoryInfo(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "grep",
		Args:    []string{"MemTotal", "/proc/meminfo"},
		Capture: true,
	})

	if err != nil {
		return err
	}

	var memKB int64
	_, _ = fmt.Sscanf(output, "MemTotal: %d kB", &memKB)
	info.MemoryGB = int(memKB / 1024 / 1024)

	return nil
}

// getDiskInfo retrieves available disk space in GB
func getDiskInfo(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-BG", "--output=avail", "/"},
		Capture: true,
	})

	if err != nil {
		return err
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) >= 2 {
		availStr := strings.TrimSuffix(strings.TrimSpace(lines[1]), "G")
		_, _ = fmt.Sscanf(availStr, "%d", &info.DiskGB)
	}

	return nil
}

// detectContainer checks if running in a container
func detectContainer() bool {
	// Check for /.dockerenv file
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check for container indicators in /proc/1/cgroup
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "lxc") ||
			strings.Contains(content, "containerd") {
			return true
		}
	}

	return false
}

// detectVM checks if running in a virtual machine
func detectVM(rc *eos_io.RuntimeContext) bool {
	// Check systemd-detect-virt
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemd-detect-virt",
		Capture: true,
	})

	if err == nil && strings.TrimSpace(output) != "none" {
		return true
	}

	return false
}

// validateOS checks OS requirements
func validateOS(info *SystemInfo, requirements SystemRequirements) error {
	if info.OS != requirements.RequiredOS {
		return fmt.Errorf("unsupported OS: %s (required: %s)", info.OS, requirements.RequiredOS)
	}

	// Compare versions
	if compareVersions(info.OSVersion, requirements.MinOSVersion) < 0 {
		return fmt.Errorf("OS version %s is below minimum required %s",
			info.OSVersion, requirements.MinOSVersion)
	}

	return nil
}

// validateResources checks resource requirements
func validateResources(info *SystemInfo, requirements SystemRequirements) error {
	var errors []string

	if info.CPUCores < requirements.MinCPUCores {
		errors = append(errors, fmt.Sprintf("insufficient CPU cores: %d (required: %d)",
			info.CPUCores, requirements.MinCPUCores))
	}

	if info.MemoryGB < requirements.MinMemoryGB {
		errors = append(errors, fmt.Sprintf("insufficient memory: %dGB (required: %dGB)",
			info.MemoryGB, requirements.MinMemoryGB))
	}

	if info.DiskGB < requirements.MinDiskGB {
		errors = append(errors, fmt.Sprintf("insufficient disk space: %dGB (required: %dGB)",
			info.DiskGB, requirements.MinDiskGB))
	}

	if len(errors) > 0 {
		return eos_err.NewUserError("%s", strings.Join(errors, "; "))
	}

	return nil
}

// validatePorts checks if required ports are available
func validatePorts(rc *eos_io.RuntimeContext, ports []int) error {
	logger := otelzap.Ctx(rc.Ctx)
	var blockedPorts []string

	// Use the service manager for better detection
	sm := NewServiceManager(rc)

	for _, port := range ports {
		// Check if port is in use using the service manager
		service := sm.getServiceFromPort(port)

		if service != nil {
			// Port is in use - check if it's an Eos-managed service
			if service.Managed {
				logger.Debug("Port in use by Eos-managed service",
					zap.Int("port", port),
					zap.String("service", service.Name),
					zap.Bool("managed", service.Managed))
				// This is fine - Eos service using the port
				continue
			}

			// Also check if it's a known Eos service by name (belt and suspenders)
			eosServices := []string{"-master", "-api", "vault", "consul", "nomad"}
			isEOSService := false
			for _, eosService := range eosServices {
				if service.Name == eosService {
					logger.Debug("Port in use by known Eos service",
						zap.Int("port", port),
						zap.String("service", service.Name))
					isEOSService = true
					break
				}
			}

			if !isEOSService {
				// Port is blocked by a non-EOS service
				blockedPorts = append(blockedPorts, fmt.Sprintf("%d (used by %s)", port, service.Name))
				logger.Debug("Port blocked by non-EOS service",
					zap.Int("port", port),
					zap.String("service", service.Name))
			}
		}
	}

	if len(blockedPorts) > 0 {
		return eos_err.NewUserError("required ports already in use by non-EOS services: %s", strings.Join(blockedPorts, ", "))
	}

	return nil
}

// getEOSServicePorts returns a map of Eos services and their ports
func getEOSServicePorts() map[string][]int {
	return map[string][]int{
		"-master": {4505, 4506},
		"-api":    {8000},
		"vault":   {8200, 8201},
		"consul":  {8300, 8301, 8302, 8500, 8600},
		"nomad":   {4646, 4647, 4648},
	}
}

// isSystemdServiceActive checks if a systemd service is active
func isSystemdServiceActive(rc *eos_io.RuntimeContext, serviceName string) bool {
	active, err := SystemctlIsActive(rc, serviceName)
	return err == nil && active
}

// checkForConflicts checks for conflicting software
func checkForConflicts(rc *eos_io.RuntimeContext) []string {
	logger := otelzap.Ctx(rc.Ctx)
	var warnings []string

	// Check for existing configuration management tools
	conflictingTools := map[string]string{
		"puppet":  "Puppet configuration management detected",
		"chef":    "Chef configuration management detected",
		"ansible": "Ansible detected (can coexist but may cause confusion)",
	}

	for tool, warning := range conflictingTools {
		if _, err := exec.LookPath(tool); err == nil {
			warnings = append(warnings, warning)
			logger.Debug("Conflicting tool detected", zap.String("tool", tool))
		}
	}

	// Check for existing HashiCorp tools with different configs
	if _, err := os.Stat("/etc/vault"); err == nil {
		warnings = append(warnings, "Existing Vault configuration detected at /etc/vault")
	}

	if _, err := os.Stat("/etc/consul"); err == nil {
		warnings = append(warnings, "Existing Consul configuration detected at /etc/consul")
	}

	if _, err := os.Stat("/etc/nomad"); err == nil {
		warnings = append(warnings, "Existing Nomad configuration detected at /etc/nomad")
	}

	return warnings
}

// checkEnvironment checks environment settings
func checkEnvironment(rc *eos_io.RuntimeContext) []string {
	var warnings []string

	// Check if running in container
	if detectContainer() {
		warnings = append(warnings, "Running in a container - some features may be limited")
	}

	// Check systemd
	if _, err := exec.LookPath("systemctl"); err != nil {
		warnings = append(warnings, "systemd not found - service management may not work properly")
	}

	// Check firewall
	if status, _ := CheckService(rc, "ufw"); status == ServiceStatusActive {
		warnings = append(warnings, "UFW firewall is active - ensure required ports are open")
	}

	// Check SELinux/AppArmor
	if _, err := os.Stat("/etc/selinux/config"); err == nil {
		warnings = append(warnings, "SELinux detected - may require additional configuration")
	}

	if _, err := os.Stat("/etc/apparmor.d"); err == nil {
		warnings = append(warnings, "AppArmor detected - may require additional configuration")
	}

	return warnings
}

// compareVersions compares two version strings (simple numeric comparison)
func compareVersions(v1, v2 string) int {
	// Simple version comparison for Ubuntu versions like "20.04", "22.04"
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		var n1, n2 int
		_, _ = fmt.Sscanf(parts1[i], "%d", &n1)
		_, _ = fmt.Sscanf(parts2[i], "%d", &n2)

		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}

	return 0
}

// PrintValidationReport outputs a formatted validation report
func PrintValidationReport(rc *eos_io.RuntimeContext, result *ValidationResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("=== System Validation Report ===")
	logger.Info("System Information:",
		zap.String("os", fmt.Sprintf("%s %s", result.SystemInfo.OS, result.SystemInfo.OSVersion)),
		zap.String("architecture", result.SystemInfo.Architecture),
		zap.Int("cpu_cores", result.SystemInfo.CPUCores),
		zap.Int("memory_gb", result.SystemInfo.MemoryGB),
		zap.Int("disk_gb", result.SystemInfo.DiskGB))

	if result.SystemInfo.IsContainer {
		logger.Info("Environment: Container")
	} else if result.SystemInfo.IsVM {
		logger.Info("Environment: Virtual Machine")
	} else {
		logger.Info("Environment: Bare Metal")
	}

	if len(result.Errors) > 0 {
		logger.Error("Validation Errors:")
		for _, err := range result.Errors {
			logger.Error("   " + err)
		}
	}

	if len(result.Warnings) > 0 {
		logger.Warn("Validation Warnings:")
		for _, warning := range result.Warnings {
			logger.Warn("  " + warning)
		}
	}

	if result.Passed {
		logger.Info(" System validation PASSED")
	} else {
		logger.Error(" System validation FAILED")
	}
}
