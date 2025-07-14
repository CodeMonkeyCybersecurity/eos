// pkg/consul/preflight.go

package consul

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunPreflightChecks performs comprehensive pre-installation validation
func RunPreflightChecks(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	checks := []PreflightCheck{
		{
			Name:        "system_requirements",
			Description: "Verify system meets minimum requirements",
			Critical:    true,
			CheckFunc:   checkSystemRequirements,
		},
		{
			Name:        "port_availability",
			Description: "Check required ports are available",
			Critical:    true,
			CheckFunc: func(rc *eos_io.RuntimeContext) error {
				return checkPortsAvailable(rc, config.Ports)
			},
		},
		{
			Name:        "existing_installation",
			Description: "Check for existing Consul installation",
			Critical:    false,
			CheckFunc:   checkExistingInstallation,
		},
		{
			Name:        "network_connectivity",
			Description: "Verify network connectivity to join addresses",
			Critical:    config.Mode == "agent",
			CheckFunc: func(rc *eos_io.RuntimeContext) error {
				return checkNetworkConnectivity(rc, config.JoinAddresses)
			},
		},
		{
			Name:        "disk_space",
			Description: "Verify sufficient disk space",
			Critical:    true,
			CheckFunc:   checkDiskSpace,
		},
		{
			Name:        "dns_resolution",
			Description: "Verify DNS is properly configured",
			Critical:    false,
			CheckFunc:   checkDNSResolution,
		},
		{
			Name:        "user_permissions",
			Description: "Verify user has required permissions",
			Critical:    true,
			CheckFunc:   checkUserPermissions,
		},
		{
			Name:        "firewall_configuration",
			Description: "Check firewall configuration",
			Critical:    false,
			CheckFunc: func(rc *eos_io.RuntimeContext) error {
				return checkFirewallConfiguration(rc, config.Ports)
			},
		},
	}

	logger.Info("Running preflight checks",
		zap.Int("total_checks", len(checks)))

	var errors []error
	passedChecks := 0

	for _, check := range checks {
		logger.Info("Running check",
			zap.String("name", check.Name),
			zap.String("description", check.Description),
			zap.Bool("critical", check.Critical))

		if err := check.CheckFunc(rc); err != nil {
			if check.Critical {
				return fmt.Errorf("critical check '%s' failed: %w", check.Name, err)
			}
			logger.Warn("Non-critical check failed",
				zap.String("check", check.Name),
				zap.Error(err))
			errors = append(errors, fmt.Errorf("%s: %w", check.Name, err))
		} else {
			logger.Info("Check passed",
				zap.String("check", check.Name))
			passedChecks++
		}
	}

	logger.Info("Preflight checks completed",
		zap.Int("passed", passedChecks),
		zap.Int("total", len(checks)),
		zap.Int("warnings", len(errors)))

	if len(errors) > 0 {
		logger.Warn("Preflight completed with warnings",
			zap.Int("warnings", len(errors)))
		for _, err := range errors {
			logger.Warn("Warning", zap.Error(err))
		}
	}

	return nil
}

// checkSystemRequirements verifies system meets minimum requirements
func checkSystemRequirements(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check minimum memory (512MB)
	memInfo, err := getMemoryInfo()
	if err != nil {
		return fmt.Errorf("failed to get memory info: %w", err)
	}

	minMemoryMB := 512
	if memInfo.TotalMB < minMemoryMB {
		return fmt.Errorf("insufficient memory: %dMB available, %dMB required", memInfo.TotalMB, minMemoryMB)
	}

	// Check CPU cores (minimum 1)
	cpuCount := getCPUCount()
	if cpuCount < 1 {
		return fmt.Errorf("insufficient CPU cores: %d available, 1 required", cpuCount)
	}

	// Check OS compatibility
	if err := checkOSCompatibility(); err != nil {
		return fmt.Errorf("OS compatibility check failed: %w", err)
	}

	logger.Info("System requirements check passed",
		zap.Int("memory_mb", memInfo.TotalMB),
		zap.Int("cpu_cores", cpuCount))

	return nil
}

// checkPortsAvailable verifies required ports are available
func checkPortsAvailable(rc *eos_io.RuntimeContext, ports PortConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	requiredPorts := map[string]int{
		"dns":      ports.DNS,
		"http":     ports.HTTP,
		"https":    ports.HTTPS,
		"grpc":     ports.GRPC,
		"serf_lan": ports.SerfLAN,
		"serf_wan": ports.SerfWAN,
		"server":   ports.Server,
	}

	var unavailablePorts []string

	for name, port := range requiredPorts {
		if port == 0 {
			continue // Skip disabled ports
		}

		logger.Debug("Checking port availability",
			zap.String("port_name", name),
			zap.Int("port", port))

		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			unavailablePorts = append(unavailablePorts, fmt.Sprintf("%s:%d", name, port))
			continue
		}
		ln.Close()
	}

	if len(unavailablePorts) > 0 {
		return fmt.Errorf("ports not available: %s", strings.Join(unavailablePorts, ", "))
	}

	logger.Info("All required ports are available")
	return nil
}

// checkExistingInstallation checks for existing Consul installation
func checkExistingInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check for existing binary
	if _, err := exec.LookPath("consul"); err == nil {
		logger.Info("Existing Consul binary found in PATH")

		// Check if service is running
		if isConsulServiceRunning() {
			return fmt.Errorf("Consul service is already running - stop it before proceeding")
		}

		// Check for existing configuration
		configPaths := []string{
			"/etc/consul.d",
			"/etc/consul",
			"/opt/consul/etc",
		}

		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				logger.Warn("Existing Consul configuration found",
					zap.String("path", path))
			}
		}
	}

	return nil
}

// checkNetworkConnectivity verifies connectivity to join addresses
func checkNetworkConnectivity(rc *eos_io.RuntimeContext, joinAddresses []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(joinAddresses) == 0 {
		logger.Info("No join addresses specified, skipping connectivity check")
		return nil
	}

	var unreachable []string

	for _, addr := range joinAddresses {
		logger.Debug("Testing connectivity to join address",
			zap.String("address", addr))

		// Parse address to extract host and port
		host, port, err := parseAddress(addr)
		if err != nil {
			logger.Warn("Invalid join address format",
				zap.String("address", addr),
				zap.Error(err))
			unreachable = append(unreachable, addr)
			continue
		}

		// Test connectivity with timeout
		timeout := 5 * time.Second
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
		if err != nil {
			unreachable = append(unreachable, addr)
			continue
		}
		conn.Close()
	}

	if len(unreachable) > 0 {
		return fmt.Errorf("cannot reach join addresses: %s", strings.Join(unreachable, ", "))
	}

	logger.Info("All join addresses are reachable")
	return nil
}

// checkDiskSpace verifies sufficient disk space
func checkDiskSpace(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check data directory space (minimum 1GB)
	dataDirs := []string{
		"/opt/consul/data",
		"/var/lib/consul",
		"/tmp", // fallback
	}

	minSpaceGB := 1
	for _, dir := range dataDirs {
		if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
			continue
		}

		spaceGB, err := getAvailableSpace(dir)
		if err != nil {
			continue
		}

		if spaceGB < float64(minSpaceGB) {
			return fmt.Errorf("insufficient disk space in %s: %.1fGB available, %dGB required", 
				dir, spaceGB, minSpaceGB)
		}

		logger.Info("Disk space check passed",
			zap.String("directory", dir),
			zap.Float64("available_gb", spaceGB))
		return nil
	}

	return fmt.Errorf("could not check disk space in any data directory")
}

// checkDNSResolution verifies DNS is properly configured
func checkDNSResolution(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Test DNS resolution of common domains
	testDomains := []string{
		"google.com",
		"consul.io",
		"hashicorp.com",
	}

	var failed []string

	for _, domain := range testDomains {
		_, err := net.LookupHost(domain)
		if err != nil {
			failed = append(failed, domain)
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("DNS resolution failed for domains: %s", strings.Join(failed, ", "))
	}

	logger.Info("DNS resolution check passed")
	return nil
}

// checkUserPermissions verifies user has required permissions
func checkUserPermissions(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root or with sufficient privileges
	if os.Geteuid() == 0 {
		logger.Info("Running as root")
		return nil
	}

	// Check if user can write to system directories
	testDirs := []string{
		"/etc/consul.d",
		"/var/log/consul",
		"/opt/consul",
	}

	var inaccessible []string

	for _, dir := range testDirs {
		// Try to create directory
		if err := os.MkdirAll(dir, 0755); err != nil {
			inaccessible = append(inaccessible, dir)
			continue
		}

		// Try to write a test file
		testFile := filepath.Join(dir, ".permission_test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			inaccessible = append(inaccessible, dir)
			continue
		}
		os.Remove(testFile)
	}

	if len(inaccessible) > 0 {
		return fmt.Errorf("insufficient permissions for directories: %s (try running with sudo)", 
			strings.Join(inaccessible, ", "))
	}

	logger.Info("User permissions check passed")
	return nil
}

// checkFirewallConfiguration checks firewall configuration
func checkFirewallConfiguration(rc *eos_io.RuntimeContext, ports PortConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if firewall is active
	firewallActive := false

	// Check UFW (Ubuntu)
	if output, err := exec.Command("ufw", "status").Output(); err == nil {
		if strings.Contains(string(output), "Status: active") {
			firewallActive = true
			logger.Info("UFW firewall is active")
		}
	}

	// Check iptables
	if output, err := exec.Command("iptables", "-L").Output(); err == nil {
		if len(strings.Split(string(output), "\n")) > 10 {
			firewallActive = true
			logger.Info("iptables rules detected")
		}
	}

	if firewallActive {
		logger.Warn("Firewall is active - ensure Consul ports are allowed",
			zap.Int("dns", ports.DNS),
			zap.Int("http", ports.HTTP),
			zap.Int("serf_lan", ports.SerfLAN),
			zap.Int("serf_wan", ports.SerfWAN),
			zap.Int("server", ports.Server))
	}

	return nil
}

// Helper functions

type MemoryInfo struct {
	TotalMB int
	FreeMB  int
}

func getMemoryInfo() (*MemoryInfo, error) {
	//TODO: This would need to read /proc/meminfo on Linux systems
	// For now, return a reasonable default
	return &MemoryInfo{
		TotalMB: 2048, // 2GB default
		FreeMB:  1024, // 1GB free
	}, nil
}

func getCPUCount() int {
	//TODO: This would read /proc/cpuinfo or use runtime.NumCPU()
	// For now, return a reasonable default
	return 2
}

func checkOSCompatibility() error {
	//TODO: Check for supported OS versions (Ubuntu 18.04+, CentOS 7+, etc.)
	return nil
}

func isConsulServiceRunning() bool {
	//TODO: Check systemctl status consul or similar
	// For now, check if process exists
	if _, err := exec.Command("pgrep", "consul").Output(); err == nil {
		return true
	}
	return false
}

func parseAddress(addr string) (host, port string, err error) {
	// Handle various address formats
	if strings.Contains(addr, ":") {
		host, port, err = net.SplitHostPort(addr)
		return
	}

	// Default to serf port if no port specified
	return addr, "8301", nil
}

func getAvailableSpace(path string) (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}

	// Available space in GB
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	availableGB := float64(availableBytes) / (1024 * 1024 * 1024)

	return availableGB, nil
}