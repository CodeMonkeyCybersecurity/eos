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

	// Check Salt configuration
	if err := discoverSaltConfiguration(rc, info); err != nil {
		logger.Warn("Failed to discover Salt configuration", zap.Error(err))
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
		zap.String("salt_mode", info.SaltMode))

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
		"salt-master", "salt-minion", "docker", "dockerd",
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

// discoverSaltConfiguration discovers current Salt configuration
func discoverSaltConfiguration(rc *eos_io.RuntimeContext, info *SystemInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check for salt-minion
	if _, err := exec.LookPath("salt-minion"); err == nil {
		if version, err := getSaltVersion(); err == nil {
			info.SaltVersion = version
		}

		// Check if minion is configured
		if configExists("/etc/salt/minion") {
			if isMasterless, err := checkMasterlessMode(); err == nil {
				if isMasterless {
					info.SaltMode = SaltModeMasterless
				} else {
					info.SaltMode = SaltModeMinion
				}
			}
		}
	}

	// Check for salt-master
	if _, err := exec.LookPath("salt-master"); err == nil {
		if configExists("/etc/salt/master") {
			info.SaltMode = SaltModeMaster
		}
	}

	if info.SaltMode == "" {
		info.SaltMode = SaltModeNone
	}

	logger.Debug("Salt configuration discovered",
		zap.String("mode", info.SaltMode),
		zap.String("version", info.SaltVersion))

	return nil
}

// getSaltVersion gets the installed Salt version
func getSaltVersion() (string, error) {
	cmd := exec.Command("salt-minion", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse version from output like "salt-minion 3006.4"
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		fields := strings.Fields(lines[0])
		if len(fields) >= 2 {
			return fields[1], nil
		}
	}

	return "", fmt.Errorf("could not parse salt version")
}

// configExists checks if a configuration file exists
func configExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

// checkMasterlessMode checks if Salt is in masterless mode
func checkMasterlessMode() (bool, error) {
	data, err := os.ReadFile("/etc/salt/minion")
	if err != nil {
		return false, err
	}

	content := string(data)
	// Check for masterless indicators
	if strings.Contains(content, "file_client: local") ||
		strings.Contains(content, "master: salt") ||
		strings.Contains(content, "#master:") {
		return true, nil
	}

	return false, nil
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

// DiscoverExistingMasters discovers existing Salt masters on the network
func DiscoverExistingMasters(rc *eos_io.RuntimeContext) ([]MasterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var masters []MasterInfo

	// 1. DNS-SD/mDNS discovery
	if dnsMasters, err := discoverDNSMasters(rc); err != nil {
		logger.Debug("Failed to discover DNS masters", zap.Error(err))
	} else {
		masters = append(masters, dnsMasters...)
	}

	// 2. Consul service discovery
	if consulMasters, err := discoverConsulMasters(rc); err != nil {
		logger.Debug("Failed to discover Consul masters", zap.Error(err))
	} else {
		masters = append(masters, consulMasters...)
	}

	// 3. Network scanning on salt ports
	if networkMasters, err := discoverNetworkMasters(rc); err != nil {
		logger.Debug("Failed to discover network masters", zap.Error(err))
	} else {
		masters = append(masters, networkMasters...)
	}

	// 4. Check known master addresses from configuration
	if configMasters, err := discoverConfigMasters(rc); err != nil {
		logger.Debug("Failed to discover config masters", zap.Error(err))
	} else {
		masters = append(masters, configMasters...)
	}

	// Deduplicate and sort masters
	masters = deduplicateMasters(masters)
	masters = sortMastersByPriority(masters)

	logger.Info("Master discovery completed", zap.Int("masters_found", len(masters)))
	return masters, nil
}

// discoverDNSMasters discovers Salt masters via DNS
func discoverDNSMasters(rc *eos_io.RuntimeContext) ([]MasterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Common DNS names for Salt masters
	dnsNames := []string{
		"salt-master",
		"salt",
		"master.salt.local",
		"salt.local",
		"salt-master.service.consul",
		"salt.service.consul",
	}

	var masters []MasterInfo

	for _, dnsName := range dnsNames {
		ips, err := net.LookupIP(dnsName)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			if ip.To4() != nil { // IPv4 only
				// Verify this is actually a Salt master
				if isValidSaltMaster(ip.String()) {
					masters = append(masters, MasterInfo{
						Address:    ip.String(),
						Datacenter: "default",
						Priority:   60,
						Status:     "dns",
					})
					logger.Debug("Found Salt master via DNS",
						zap.String("dns_name", dnsName),
						zap.String("address", ip.String()))
				}
			}
		}
	}

	return masters, nil
}

// discoverConsulMasters discovers Salt masters registered in Consul
func discoverConsulMasters(rc *eos_io.RuntimeContext) ([]MasterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Consul is available
	if _, err := exec.LookPath("consul"); err != nil {
		logger.Debug("Consul not available, skipping Consul master discovery")
		return []MasterInfo{}, nil
	}

	// Query Consul for Salt master services
	cmd := exec.Command("consul", "catalog", "service", "salt-master", "-format=json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query Consul: %w", err)
	}

	// Parse Consul response
	var services []map[string]interface{}
	if err := json.Unmarshal(output, &services); err != nil {
		return nil, fmt.Errorf("failed to parse Consul response: %w", err)
	}

	var masters []MasterInfo
	for _, service := range services {
		address, addressOk := service["ServiceAddress"].(string)
		port, portOk := service["ServicePort"].(float64)
		datacenter, dcOk := service["Datacenter"].(string)

		if addressOk && portOk {
			// Use the address:port format if port is specified
			if port != 0 {
				address = fmt.Sprintf("%s:%d", address, int(port))
			}

			if !dcOk {
				datacenter = "default"
			}

			masters = append(masters, MasterInfo{
				Address:    address,
				Datacenter: datacenter,
				Priority:   80, // High priority for Consul-registered masters
				Status:     "consul",
			})

			logger.Debug("Found Salt master via Consul",
				zap.String("address", address),
				zap.String("datacenter", datacenter))
		}
	}

	return masters, nil
}

// discoverNetworkMasters discovers Salt masters via network scanning
func discoverNetworkMasters(rc *eos_io.RuntimeContext) ([]MasterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var masters []MasterInfo

	// Get local network interfaces to determine scan ranges
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			// Scan this network for Salt masters (limited scan for performance)
			if networkMasters, err := scanNetworkRange(rc, ipNet); err != nil {
				logger.Debug("Failed to scan network range",
					zap.String("range", ipNet.String()),
					zap.Error(err))
			} else {
				masters = append(masters, networkMasters...)
			}
		}
	}

	return masters, nil
}

// scanNetworkRange scans a specific network range for Salt masters
func scanNetworkRange(rc *eos_io.RuntimeContext, ipNet *net.IPNet) ([]MasterInfo, error) {
	var masters []MasterInfo

	// For performance, only scan common server IP addresses
	commonHosts := []string{
		".1",   // Common gateway/server IP
		".10",  // Common server IP
		".100", // Common server IP
		".254", // Common server IP
	}

	baseIP := ipNet.IP.To4()
	if baseIP == nil {
		return masters, nil
	}

	// Convert network to base IP
	networkIP := baseIP.Mask(ipNet.Mask)

	for _, hostSuffix := range commonHosts {
		// Construct IP address
		testIP := fmt.Sprintf("%d.%d.%d%s", networkIP[0], networkIP[1], networkIP[2], hostSuffix)

		// Test if this IP has a Salt master
		if isValidSaltMaster(testIP) {
			masters = append(masters, MasterInfo{
				Address:    testIP,
				Datacenter: "default",
				Priority:   40, // Lower priority for network-discovered masters
				Status:     "network",
			})
		}
	}

	return masters, nil
}

// discoverConfigMasters discovers masters from configuration files
func discoverConfigMasters(rc *eos_io.RuntimeContext) ([]MasterInfo, error) {
	var masters []MasterInfo

	// Check existing Salt configuration
	if _, err := os.Stat("/etc/salt/minion"); err == nil {
		if configMasters, err := parseMastersFromConfig("/etc/salt/minion"); err == nil {
			masters = append(masters, configMasters...)
		}
	}

	// Check for eos-specific configuration files
	eosConfigPaths := []string{
		"/etc/eos/masters.conf",
		"/var/lib/eos/masters.conf",
		"/opt/eos/masters.conf",
	}

	for _, configPath := range eosConfigPaths {
		if _, err := os.Stat(configPath); err == nil {
			if configMasters, err := parseMastersFromConfig(configPath); err == nil {
				masters = append(masters, configMasters...)
			}
		}
	}

	return masters, nil
}

// parseMastersFromConfig parses master addresses from configuration files
func parseMastersFromConfig(configPath string) ([]MasterInfo, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var masters []MasterInfo
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for master configuration
		if strings.HasPrefix(line, "master:") {
			masterAddr := strings.TrimSpace(strings.TrimPrefix(line, "master:"))
			masterAddr = strings.Trim(masterAddr, "\"'")

			if masterAddr != "" && masterAddr != "salt" && masterAddr != "localhost" {
				masters = append(masters, MasterInfo{
					Address:    masterAddr,
					Datacenter: "default",
					Priority:   90, // Highest priority for configured masters
					Status:     "config",
				})
			}
		}
	}

	return masters, nil
}

// isValidSaltMaster tests if an IP address is running a Salt master
func isValidSaltMaster(address string) bool {
	// Test both Salt ports
	saltPorts := []int{SaltPublisherPort, SaltRequestPort}

	for _, port := range saltPorts {
		testAddr := fmt.Sprintf("%s:%d", address, port)
		conn, err := net.DialTimeout("tcp", testAddr, 2*time.Second)
		if err != nil {
			continue
		}
		if err := conn.Close(); err != nil {
			// Log error but don't return it as this is just a connectivity test
		}
		return true // If we can connect to either port, assume it's a Salt master
	}

	return false
}

// deduplicateMasters removes duplicate masters from the list
func deduplicateMasters(masters []MasterInfo) []MasterInfo {
	seen := make(map[string]bool)
	var result []MasterInfo

	for _, master := range masters {
		key := master.Address + ":" + master.Datacenter
		if !seen[key] {
			seen[key] = true
			result = append(result, master)
		}
	}

	return result
}

// sortMastersByPriority sorts masters by priority (highest first)
func sortMastersByPriority(masters []MasterInfo) []MasterInfo {
	// Simple insertion sort by priority
	for i := 1; i < len(masters); i++ {
		key := masters[i]
		j := i - 1

		// Move elements with lower priority to the right
		for j >= 0 && masters[j].Priority < key.Priority {
			masters[j+1] = masters[j]
			j--
		}
		masters[j+1] = key
	}

	return masters
}

// selectBestMaster selects the best master from available options
func selectBestMaster(rc *eos_io.RuntimeContext, masters []MasterInfo, info *SystemInfo) *MasterInfo {
	logger := otelzap.Ctx(rc.Ctx)

	if len(masters) == 0 {
		return nil
	}

	// Score each master based on multiple factors
	var bestMaster *MasterInfo
	bestScore := -1

	for _, master := range masters {
		score := scoreMaster(rc, &master, info)

		logger.Debug("Scored master candidate",
			zap.String("address", master.Address),
			zap.String("datacenter", master.Datacenter),
			zap.Int("score", score))

		if score > bestScore {
			bestScore = score
			bestMaster = &master
		}
	}

	if bestMaster != nil {
		logger.Info("Selected best master",
			zap.String("address", bestMaster.Address),
			zap.String("datacenter", bestMaster.Datacenter),
			zap.Int("score", bestScore))
	}

	return bestMaster
}

// scoreMaster scores a master based on multiple factors
func scoreMaster(rc *eos_io.RuntimeContext, master *MasterInfo, info *SystemInfo) int {
	score := 0

	// Base score from priority
	score += master.Priority

	// Datacenter locality bonus
	if master.Datacenter != "" && master.Datacenter != "default" {
		score += 10 // Bonus for defined datacenter
	}

	// Network connectivity test
	if testMasterConnectivity(rc, master.Address) {
		score += 20 // Bonus for reachable master
	} else {
		score -= 50 // Penalty for unreachable master
	}

	// Resource availability check
	if info.HasSufficientResources() {
		score += 5 // Bonus if this system has resources to be a good minion
	}

	// Discovery method bonus
	switch master.Status {
	case "config":
		score += 15 // Configured masters get highest bonus
	case "consul":
		score += 10 // Consul-discovered masters get medium bonus
	case "dns":
		score += 5 // DNS-discovered masters get small bonus
	case "network":
		score += 0 // Network-discovered masters get no bonus
	}

	return score
}

// testMasterConnectivity tests if a master is reachable
func testMasterConnectivity(rc *eos_io.RuntimeContext, address string) bool {
	// Test both Salt ports
	saltPorts := []int{SaltPublisherPort, SaltRequestPort}

	for _, port := range saltPorts {
		testAddr := fmt.Sprintf("%s:%d", address, port)
		conn, err := net.DialTimeout("tcp", testAddr, 3*time.Second)
		if err != nil {
			continue
		}
		if err := conn.Close(); err != nil {
			// Log error but don't return it as this is just a connectivity test
		}
		return true // If we can connect to either port, master is reachable
	}

	return false
}

// GetSelectedMaster returns the best master for a given system
func GetSelectedMaster(rc *eos_io.RuntimeContext, info *SystemInfo) (*MasterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Discover available masters
	masters, err := DiscoverExistingMasters(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to discover masters: %w", err)
	}

	if len(masters) == 0 {
		logger.Info("No masters discovered")
		return nil, nil
	}

	// Select the best master
	selectedMaster := selectBestMaster(rc, masters, info)
	if selectedMaster == nil {
		return nil, fmt.Errorf("no suitable master found")
	}

	return selectedMaster, nil
}

// DetermineRole determines the appropriate role for this server
func DetermineRole(rc *eos_io.RuntimeContext, info *SystemInfo) string {
	logger := otelzap.Ctx(rc.Ctx)

	// Query existing infrastructure
	masters, err := DiscoverExistingMasters(rc)
	if err != nil {
		logger.Warn("Failed to discover existing masters", zap.Error(err))
		masters = []MasterInfo{}
	}

	if len(masters) == 0 {
		logger.Info("No existing masters found, promoting to master role")
		return RoleMaster
	}

	// Smart master selection logic
	selectedMaster := selectBestMaster(rc, masters, info)

	// Determine if this system should be a master or minion
	if selectedMaster != nil {
		logger.Info("Selected master for minion role",
			zap.String("master_address", selectedMaster.Address),
			zap.String("master_datacenter", selectedMaster.Datacenter),
			zap.String("selection_reason", selectedMaster.Status))
		return RoleMinion
	} else {
		// No suitable master found, promote to master
		logger.Info("No suitable master found, promoting to master role")
		return RoleMaster
	}
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
