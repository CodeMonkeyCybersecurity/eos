// pkg/bootstrap/health_check.go

package bootstrap

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HealthCheckResult contains the results of health checks
type HealthCheckResult struct {
	Passed       bool
	Checks       []HealthCheck
	FailedChecks []string
	Warnings     []string
}

// HealthCheck represents a single health check
type HealthCheck struct {
	Name        string
	Description string
	Passed      bool
	Message     string
	Critical    bool // If true, failure blocks joining
}

// PerformHealthChecks runs all health checks before joining cluster
func PerformHealthChecks(rc *eos_io.RuntimeContext, consulAddr string) (*HealthCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting pre-join health checks")

	result := &HealthCheckResult{
		Passed: true,
		Checks: []HealthCheck{},
	}

	// Run all checks
	checks := []func(*eos_io.RuntimeContext, string) HealthCheck{
		checkOSCompatibility,
		checkDiskSpace,
		checkMemory,
		checkNetworkConnectivity,
		checkTimeSynchronization,
		checkPortAvailability,
		checkHostnameResolution,
		checkExistingServices,
	}

	for _, checkFunc := range checks {
		check := checkFunc(rc, consulAddr)
		result.Checks = append(result.Checks, check)

		if !check.Passed {
			if check.Critical {
				result.Passed = false
				result.FailedChecks = append(result.FailedChecks, check.Name)
				logger.Error("Critical health check failed",
					zap.String("check", check.Name),
					zap.String("message", check.Message))
			} else {
				result.Warnings = append(result.Warnings, check.Message)
				logger.Warn("Health check warning",
					zap.String("check", check.Name),
					zap.String("message", check.Message))
			}
		} else {
			logger.Debug("Health check passed", zap.String("check", check.Name))
		}
	}

	return result, nil
}

// checkOSCompatibility verifies OS is supported
func checkOSCompatibility(rc *eos_io.RuntimeContext, consulAddr string) HealthCheck {
	check := HealthCheck{
		Name:        "OS Compatibility",
		Description: "Verify operating system is supported",
		Critical:    true,
	}

	// Check if Ubuntu
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "lsb_release",
		Args:    []string{"-is"},
		Capture: true,
	})
	if err != nil || !strings.Contains(strings.ToLower(output), "ubuntu") {
		check.Passed = false
		check.Message = "EOS requires Ubuntu Linux"
		return check
	}

	// Check version
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "lsb_release",
		Args:    []string{"-rs"},
		Capture: true,
	})
	if err != nil {
		check.Passed = false
		check.Message = "Failed to determine OS version"
		return check
	}

	version := strings.TrimSpace(output)
	if version < "20.04" {
		check.Passed = false
		check.Message = fmt.Sprintf("Ubuntu %s is too old, requires 20.04+", version)
		return check
	}

	check.Passed = true
	check.Message = fmt.Sprintf("Ubuntu %s is supported", version)
	return check
}

// checkDiskSpace verifies sufficient disk space
func checkDiskSpace(rc *eos_io.RuntimeContext, consulAddr string) HealthCheck {
	check := HealthCheck{
		Name:        "Disk Space",
		Description: "Verify sufficient disk space available",
		Critical:    true,
	}

	// Check root filesystem
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-BG", "/"},
		Capture: true,
	})
	if err != nil {
		check.Passed = false
		check.Message = "Failed to check disk space"
		return check
	}

	// Parse df output
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		check.Passed = false
		check.Message = "Failed to parse disk space"
		return check
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		check.Passed = false
		check.Message = "Failed to parse disk space"
		return check
	}

	// Extract available space in GB
	availStr := strings.TrimSuffix(fields[3], "G")
	var availGB int
	fmt.Sscanf(availStr, "%d", &availGB)

	if availGB < 10 {
		check.Passed = false
		check.Message = fmt.Sprintf("Insufficient disk space: %dGB available, need at least 10GB", availGB)
		return check
	}

	check.Passed = true
	check.Message = fmt.Sprintf("%dGB available", availGB)
	return check
}

// checkMemory verifies sufficient memory
func checkMemory(rc *eos_io.RuntimeContext, consulAddr string) HealthCheck {
	check := HealthCheck{
		Name:        "Memory",
		Description: "Verify sufficient memory available",
		Critical:    false, // Warning only
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "free",
		Args:    []string{"-g"},
		Capture: true,
	})
	if err != nil {
		check.Passed = false
		check.Message = "Failed to check memory"
		return check
	}

	// Parse free output
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		check.Passed = false
		check.Message = "Failed to parse memory"
		return check
	}

	// Find Mem: line
	for _, line := range lines {
		if strings.HasPrefix(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				var totalGB int
				fmt.Sscanf(fields[1], "%d", &totalGB)

				if totalGB < 4 {
					check.Passed = false
					check.Message = fmt.Sprintf("Low memory: %dGB total, recommend at least 4GB", totalGB)
					return check
				}

				check.Passed = true
				check.Message = fmt.Sprintf("%dGB total memory", totalGB)
				return check
			}
		}
	}

	check.Passed = false
	check.Message = "Failed to determine memory"
	return check
}

// checkNetworkConnectivity verifies network connectivity to master
func checkNetworkConnectivity(rc *eos_io.RuntimeContext, consulAddr string) HealthCheck {
	check := HealthCheck{
		Name:        "Network Connectivity",
		Description: "Verify network connectivity to master",
		Critical:    true,
	}

	// Ping the master
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ping",
		Args:    []string{"-c", "3", "-W", "2", consulAddr},
		Capture: true,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		check.Passed = false
		check.Message = fmt.Sprintf("Cannot reach master at %s", consulAddr)
		return check
	}

	check.Passed = true
	check.Message = "Network connectivity verified"
	return check
}

// checkTimeSynchronization verifies time is synchronized
func checkTimeSynchronization(rc *eos_io.RuntimeContext, consulAddr string) HealthCheck {
	check := HealthCheck{
		Name:        "Time Synchronization",
		Description: "Verify system time is synchronized",
		Critical:    false, // Warning only
	}

	// Check if NTP is synchronized
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "timedatectl",
		Args:    []string{"status"},
		Capture: true,
	})
	if err != nil {
		check.Passed = false
		check.Message = "Failed to check time synchronization"
		return check
	}

	if !strings.Contains(output, "System clock synchronized: yes") {
		check.Passed = false
		check.Message = "System time is not synchronized"
		return check
	}

	check.Passed = true
	check.Message = "Time is synchronized"
	return check
}

// checkPortAvailability verifies required ports are available
func checkPortAvailability(rc *eos_io.RuntimeContext, consulAddr string) HealthCheck {
	check := HealthCheck{
		Name:        "Port Availability",
		Description: "Verify required ports are available",
		Critical:    false,
	}

	// Check common ports that might conflict
	ports := map[int]string{
		80:   "HTTP",
		443:  "HTTPS",
		8080: "HTTP Alt",
		3306: "MySQL",
		5432: "PostgreSQL",
	}

	var usedPorts []string
	for port, service := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			usedPorts = append(usedPorts, fmt.Sprintf("%d (%s)", port, service))
		} else {
			ln.Close()
		}
	}

	if len(usedPorts) > 0 {
		check.Passed = false
		check.Message = fmt.Sprintf("Ports in use: %s", strings.Join(usedPorts, ", "))
		check.Critical = false // Just a warning
		return check
	}

	check.Passed = true
	check.Message = "All common ports available"
	return check
}

// checkHostnameResolution verifies hostname resolution
func checkHostnameResolution(rc *eos_io.RuntimeContext, consulAddr string) HealthCheck {
	check := HealthCheck{
		Name:        "Hostname Resolution",
		Description: "Verify hostname resolution is working",
		Critical:    true,
	}

	hostname, err := os.Hostname()
	if err != nil {
		check.Passed = false
		check.Message = "Failed to get hostname"
		return check
	}

	// Check if hostname resolves
	ips, err := net.LookupHost(hostname)
	if err != nil || len(ips) == 0 {
		check.Passed = false
		check.Message = fmt.Sprintf("Hostname %s does not resolve", hostname)
		return check
	}

	// Check FQDN
	fqdn, err := os.Hostname() // Would use proper FQDN lookup
	if err != nil || fqdn == "localhost" || fqdn == "localhost.localdomain" {
		check.Passed = false
		check.Message = "Invalid FQDN configuration"
		return check
	}

	check.Passed = true
	check.Message = fmt.Sprintf("Hostname %s resolves correctly", hostname)
	return check
}

// checkExistingServices checks for conflicting services
func checkExistingServices(rc *eos_io.RuntimeContext, consulAddr string) HealthCheck {
	check := HealthCheck{
		Name:        "Service Conflicts",
		Description: "Check for conflicting services",
		Critical:    false,
	}

	// Services that might conflict
	services := []string{
		"puppet",
		"chef-client",
		"ansible-pull",
	}

	var activeServices []string
	for _, service := range services {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", service},
			Capture: true,
		})
		if err == nil && strings.TrimSpace(output) == "active" {
			activeServices = append(activeServices, service)
		}
	}

	if len(activeServices) > 0 {
		check.Passed = false
		check.Message = fmt.Sprintf("Conflicting services active: %s", strings.Join(activeServices, ", "))
		check.Critical = false // Just a warning
		return check
	}

	check.Passed = true
	check.Message = "No conflicting services found"
	return check
}
