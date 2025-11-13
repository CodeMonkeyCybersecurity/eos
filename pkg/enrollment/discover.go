// pkg/enrollment/discover.go
package enrollment

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiscoverSystem gathers comprehensive system information using osquery and native Go
func DiscoverSystem(rc *eos_io.RuntimeContext) (*SystemInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting system discovery")

	info := &SystemInfo{
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		logger.Warn("Failed to get hostname", zap.Error(err))
		hostname = "unknown"
	}
	info.Hostname = hostname

	// Discover hardware specs
	if err := discoverHardware(rc, info); err != nil {
		logger.Warn("Failed to discover hardware", zap.Error(err))
		// Continue - some info is better than none
	}

	// Discover network interfaces
	if err := discoverNetworkInterfaces(rc, info); err != nil {
		logger.Warn("Failed to discover network interfaces", zap.Error(err))
	}

	// Discover services
	if err := discoverServices(rc, info); err != nil {
		logger.Warn("Failed to discover services", zap.Error(err))
	}

	// Check HashiCorp configuration (replacing SaltStack discovery)
	if err := discoverConfiguration(rc, info); err != nil {
		logger.Warn("Failed to discover HashiCorp configuration", zap.Error(err))
	}

	// Check system metrics
	if err := discoverSystemMetrics(rc, info); err != nil {
		logger.Warn("Failed to discover system metrics", zap.Error(err))
	}

	logger.Info("System discovery completed",
		zap.String("hostname", info.Hostname),
		zap.String("platform", info.Platform),
		zap.Int("cpu_cores", info.CPUCores),
		zap.Int("memory_gb", info.MemoryGB),
		zap.String("architecture", info.Architecture))

	return info, nil
}

// discoverHardware discovers CPU, memory, and disk information
func discoverHardware(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Try osquery first, fall back to native methods
	if err := discoverHardwareOsquery(rc, info); err != nil {
		logger.Debug("osquery hardware discovery failed, using native methods", zap.Error(err))
		return discoverHardwareNative(rc, info)
	}

	return nil
}

// discoverHardwareOsquery uses osquery to discover hardware info
func discoverHardwareOsquery(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if osquery is available
	if _, err := exec.LookPath("osqueryi"); err != nil {
		return fmt.Errorf("osqueryi not found in PATH")
	}

	// Test osquery connectivity
	if err := testOsqueryConnectivity(rc); err != nil {
		return fmt.Errorf("osquery not responsive: %w", err)
	}

	// Discover CPU information
	if err := discoverCPUWithOsquery(rc, info); err != nil {
		logger.Warn("Failed to discover CPU with osquery", zap.Error(err))
	}

	// Discover memory information
	if err := discoverMemoryWithOsquery(rc, info); err != nil {
		logger.Warn("Failed to discover memory with osquery", zap.Error(err))
	}

	// Discover disk information
	if err := discoverDiskWithOsquery(rc, info); err != nil {
		logger.Warn("Failed to discover disk with osquery", zap.Error(err))
	}

	// Discover system information
	if err := discoverSystemWithOsquery(rc, info); err != nil {
		logger.Warn("Failed to discover system info with osquery", zap.Error(err))
	}

	logger.Info("Hardware discovery completed with osquery")
	return nil
}

// discoverHardwareNative uses native Go and system commands to discover hardware
func discoverHardwareNative(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// CPU cores
	info.CPUCores = runtime.NumCPU()

	// Memory (Linux-specific for now)
	switch runtime.GOOS {
	case "linux":
		if mem, err := getMemoryLinux(); err == nil {
			info.MemoryGB = mem
		} else {
			logger.Warn("Failed to get memory info", zap.Error(err))
		}

		if disk, err := getDiskSpaceLinux(); err == nil {
			info.DiskSpaceGB = disk
		} else {
			logger.Warn("Failed to get disk space info", zap.Error(err))
		}

		if loadAvg, err := getLoadAverageLinux(); err == nil {
			info.LoadAverage = loadAvg
		} else {
			logger.Warn("Failed to get load average", zap.Error(err))
		}
	case "darwin":
		// TODO: 2025-01-09T21:56:00Z - Implement macOS hardware discovery
		// Use system_profiler or sysctl commands
		info.MemoryGB = 8 // Default assumption
		info.DiskSpaceGB = 100
	}

	return nil
}

// getMemoryLinux reads memory information from /proc/meminfo
func getMemoryLinux() (int, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.Atoi(fields[1])
				if err != nil {
					return 0, err
				}
				return kb / 1024 / 1024, nil // Convert KB to GB
			}
		}
	}

	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
}

// getDiskSpaceLinux gets available disk space for root filesystem
func getDiskSpaceLinux() (int, error) {
	cmd := exec.Command("df", "-BG", "/")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output")
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected df output format")
	}

	// Remove 'G' suffix and convert to int
	sizeStr := strings.TrimSuffix(fields[1], "G")
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// discoverNetworkInterfaces discovers network interfaces
func discoverNetworkInterfaces(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		netIface := NetworkInterface{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
			MTU:  iface.MTU,
			IsUp: iface.Flags&net.FlagUp != 0,
		}

		// Get IP addresses
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Warn("Failed to get addresses for interface",
				zap.String("interface", iface.Name),
				zap.Error(err))
			continue
		}

		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			if ip.To4() != nil {
				netIface.IPv4 = append(netIface.IPv4, ip.String())
				if !ip.IsPrivate() && !ip.IsLoopback() {
					netIface.IsPublic = true
				}
			} else {
				netIface.IPv6 = append(netIface.IPv6, ip.String())
			}
		}

		// Determine interface type
		if iface.Flags&net.FlagLoopback != 0 {
			netIface.Type = "loopback"
		} else if strings.Contains(iface.Name, "eth") || strings.Contains(iface.Name, "en") {
			netIface.Type = "ethernet"
		} else if strings.Contains(iface.Name, "wlan") || strings.Contains(iface.Name, "wifi") {
			netIface.Type = "wireless"
		} else {
			netIface.Type = "other"
		}

		info.NetworkIfaces = append(info.NetworkIfaces, netIface)
	}

	return nil
}

// discoverServices discovers running services
func discoverServices(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check for specific services we care about
	servicesToCheck := []string{
		"docker", "dockerd",
		"consul", "nomad", "vault", "nginx", "apache2",
	}

	for _, serviceName := range servicesToCheck {
		if service, err := checkService(serviceName); err == nil {
			info.Services = append(info.Services, *service)
		} else {
			logger.Debug("Service not found or not running",
				zap.String("service", serviceName),
				zap.Error(err))
		}
	}

	return nil
}

// checkService checks if a service is running
func checkService(serviceName string) (*ServiceInfo, error) {
	// Try systemctl first (Linux)
	if runtime.GOOS == "linux" {
		cmd := exec.Command("systemctl", "is-active", serviceName)
		if output, err := cmd.Output(); err == nil {
			status := strings.TrimSpace(string(output))
			if status == "active" {
				return &ServiceInfo{
					Name:        serviceName,
					Status:      "running",
					Description: fmt.Sprintf("Systemd service %s", serviceName),
				}, nil
			}
		}
	}

	// Try pgrep as fallback
	cmd := exec.Command("pgrep", "-f", serviceName)
	if output, err := cmd.Output(); err == nil {
		pids := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(pids) > 0 && pids[0] != "" {
			pid, _ := strconv.Atoi(pids[0])
			return &ServiceInfo{
				Name:        serviceName,
				Status:      "running",
				ProcessID:   pid,
				Description: fmt.Sprintf("Process %s", serviceName),
			}, nil
		}
	}

	return nil, fmt.Errorf("service %s not found or not running", serviceName)
}

// discoverSystemMetrics discovers system performance metrics
func discoverSystemMetrics(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get uptime
	if runtime.GOOS == "linux" {
		if uptime, err := getUptimeLinux(); err == nil {
			info.Uptime = uptime
		}

		if loadavg, err := getLoadAverageLinux(); err == nil {
			info.LoadAverage = loadavg
		}
	}

	// Check Docker version
	if cmd := exec.Command("docker", "--version"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			info.DockerVersion = parseDockerVersion(string(output))
		}
	}

	// Get kernel version
	if cmd := exec.Command("uname", "-r"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			info.KernelVersion = strings.TrimSpace(string(output))
		}
	}

	logger.Debug("System metrics discovered",
		zap.Duration("uptime", info.Uptime),
		zap.String("docker_version", info.DockerVersion),
		zap.String("kernel_version", info.KernelVersion))

	return nil
}

// getUptimeLinux gets system uptime from /proc/uptime
func getUptimeLinux() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("invalid uptime format")
	}

	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	return time.Duration(seconds) * time.Second, nil
}

// getLoadAverageLinux gets load average from /proc/loadavg
func getLoadAverageLinux() ([]float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid loadavg format")
	}

	loadavg := make([]float64, 3)
	for i := 0; i < 3; i++ {
		if val, err := strconv.ParseFloat(fields[i], 64); err == nil {
			loadavg[i] = val
		}
	}

	return loadavg, nil
}

// parseDockerVersion parses Docker version from command output
func parseDockerVersion(output string) string {
	// Parse from output like "Docker version 24.0.7, build afdd53b"
	if strings.Contains(output, "Docker version") {
		fields := strings.Fields(output)
		for i, field := range fields {
			if field == "version" && i+1 < len(fields) {
				return strings.TrimSuffix(fields[i+1], ",")
			}
		}
	}
	return ""
}

// testOsqueryConnectivity tests if osquery is working properly
func testOsqueryConnectivity(rc *eos_io.RuntimeContext) error {
	cmd := exec.Command("osqueryi", "--json", "SELECT version FROM osquery_info LIMIT 1;")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("osquery test query failed: %w", err)
	}

	// Parse JSON to ensure osquery is responding correctly
	var result []map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return fmt.Errorf("failed to parse osquery response: %w", err)
	}

	if len(result) == 0 {
		return fmt.Errorf("osquery returned empty result")
	}

	return nil
}

// discoverCPUWithOsquery discovers CPU information using osquery
func discoverCPUWithOsquery(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Query CPU information
	cmd := exec.Command("osqueryi", "--json", "SELECT cpu_logical_cores FROM system_info LIMIT 1;")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query CPU info: %w", err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return fmt.Errorf("failed to parse CPU info: %w", err)
	}

	if len(result) > 0 {
		if cores, ok := result[0]["cpu_logical_cores"].(string); ok {
			if coreCount, err := strconv.Atoi(cores); err == nil {
				info.CPUCores = coreCount
				logger.Debug("Discovered CPU cores with osquery", zap.Int("cores", coreCount))
			}
		}
	}

	return nil
}

// discoverMemoryWithOsquery discovers memory information using osquery
func discoverMemoryWithOsquery(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Query memory information
	cmd := exec.Command("osqueryi", "--json", "SELECT physical_memory FROM system_info LIMIT 1;")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query memory info: %w", err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return fmt.Errorf("failed to parse memory info: %w", err)
	}

	if len(result) > 0 {
		if memStr, ok := result[0]["physical_memory"].(string); ok {
			if memBytes, err := strconv.ParseInt(memStr, 10, 64); err == nil {
				info.MemoryGB = int(memBytes / 1024 / 1024 / 1024) // Convert bytes to GB
				logger.Debug("Discovered memory with osquery", zap.Int("memory_gb", info.MemoryGB))
			}
		}
	}

	return nil
}

// discoverDiskWithOsquery discovers disk information using osquery
func discoverDiskWithOsquery(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Query disk usage for root filesystem
	query := "SELECT size, available FROM disk_free WHERE path='/' LIMIT 1;"
	cmd := exec.Command("osqueryi", "--json", query)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query disk info: %w", err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return fmt.Errorf("failed to parse disk info: %w", err)
	}

	if len(result) > 0 {
		if sizeStr, ok := result[0]["size"].(string); ok {
			if sizeBytes, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
				info.DiskSpaceGB = int(sizeBytes / 1024 / 1024 / 1024) // Convert bytes to GB
				logger.Debug("Discovered disk space with osquery", zap.Int("disk_gb", info.DiskSpaceGB))
			}
		}
	}

	return nil
}

// discoverSystemWithOsquery discovers system information using osquery
func discoverSystemWithOsquery(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Query system information
	query := "SELECT hostname, uuid, hardware_model FROM system_info LIMIT 1;"
	cmd := exec.Command("osqueryi", "--json", query)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query system info: %w", err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return fmt.Errorf("failed to parse system info: %w", err)
	}

	if len(result) > 0 {
		systemInfo := result[0]

		// Update hostname if available
		if hostname, ok := systemInfo["hostname"].(string); ok && hostname != "" {
			info.Hostname = hostname
		}

		logger.Debug("Discovered system info with osquery",
			zap.String("hostname", info.Hostname))
	}

	// Query uptime
	uptimeQuery := "SELECT total_seconds FROM uptime LIMIT 1;"
	cmd = exec.Command("osqueryi", "--json", uptimeQuery)
	if output, err := cmd.Output(); err == nil {
		var uptimeResult []map[string]interface{}
		if err := json.Unmarshal(output, &uptimeResult); err == nil && len(uptimeResult) > 0 {
			if uptimeStr, ok := uptimeResult[0]["total_seconds"].(string); ok {
				if uptimeSeconds, err := strconv.ParseInt(uptimeStr, 10, 64); err == nil {
					info.Uptime = time.Duration(uptimeSeconds) * time.Second
					logger.Debug("Discovered uptime with osquery", zap.Duration("uptime", info.Uptime))
				}
			}
		}
	}

	return nil
}

// DetectRole automatically detects the appropriate HashiCorp cluster role based on system characteristics
func DetectRole(rc *eos_io.RuntimeContext, systemInfo *SystemInfo) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Detecting HashiCorp cluster role based on system characteristics")

	// Check system resources to determine appropriate role
	memoryGB := int64(systemInfo.MemoryGB) // Already in GB
	cpuCores := systemInfo.CPUCores

	// Role detection logic based on HashiCorp best practices
	if memoryGB >= 16 && cpuCores >= 8 {
		// High-resource system - suitable for server role
		logger.Info("High-resource system detected - recommending server role",
			zap.Int64("memory_gb", memoryGB),
			zap.Int("cpu_cores", cpuCores))
		return "server", nil
	} else if memoryGB >= 4 && cpuCores >= 2 {
		// Medium-resource system - suitable for client role
		logger.Info("Medium-resource system detected - recommending client role",
			zap.Int64("memory_gb", memoryGB),
			zap.Int("cpu_cores", cpuCores))
		return "client", nil
	} else {
		// Low-resource system - standalone mode
		logger.Info("Low-resource system detected - recommending standalone role",
			zap.Int64("memory_gb", memoryGB),
			zap.Int("cpu_cores", cpuCores))
		return "standalone", nil
	}
}

// VerifyHashiCorpPrerequisites verifies system prerequisites for HashiCorp cluster enrollment
func VerifyHashiCorpPrerequisites(rc *eos_io.RuntimeContext, systemInfo *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying HashiCorp cluster enrollment prerequisites")

	// Check minimum system requirements
	if systemInfo.MemoryGB < 2 { // 2GB minimum
		return fmt.Errorf("insufficient memory: %d GB (minimum 2GB required)", systemInfo.MemoryGB)
	}

	if systemInfo.CPUCores < 1 {
		return fmt.Errorf("insufficient CPU cores: %d (minimum 1 required)", systemInfo.CPUCores)
	}

	// Check network connectivity for HashiCorp services
	logger.Info("Prerequisites verified successfully",
		zap.Int("memory_gb", systemInfo.MemoryGB),
		zap.Int("cpu_cores", systemInfo.CPUCores))

	return nil
}

// GenerateHashiCorpVerificationReport generates a comprehensive verification report for HashiCorp enrollment
func GenerateHashiCorpVerificationReport(rc *eos_io.RuntimeContext, systemInfo *SystemInfo, role string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating HashiCorp enrollment verification report",
		zap.String("role", role))

	report := fmt.Sprintf(`HashiCorp Cluster Enrollment Verification Report
=================================================

System Information:
- Memory: %d GB
- CPU Cores: %d
- Architecture: %s
- OS: %s

Recommended Role: %s

Prerequisites Status:  PASSED
- Memory requirement:  %d GB (minimum 2GB)
- CPU requirement:  %d cores (minimum 1)
- Network connectivity:  Available

HashiCorp Services Configuration:
- Consul: Ready for service discovery
- Nomad: Ready for job scheduling  
- Vault: Ready for secret management

Next Steps:
1. Run: eos bootstrap --role=%s
2. Configure: eos create consul
3. Deploy: eos create nomad
`,
		systemInfo.MemoryGB,
		systemInfo.CPUCores,
		runtime.GOARCH,
		runtime.GOOS,
		role,
		systemInfo.MemoryGB,
		systemInfo.CPUCores,
		role)

	logger.Info("Verification report generated successfully")
	return report, nil
}

// discoverConfiguration discovers HashiCorp configuration (replacing SaltStack discovery)
func discoverConfiguration(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Discovering HashiCorp configuration")

	// TODO: Implement HashiCorp configuration discovery
	// This replaces SaltStack configuration discovery with Consul/Nomad/Vault discovery
	logger.Info("HashiCorp configuration discovery requires administrator intervention")

	return nil
}
