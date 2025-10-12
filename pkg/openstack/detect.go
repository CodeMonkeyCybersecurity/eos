package openstack

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DetectExistingInstallation checks for an existing OpenStack installation
func DetectExistingInstallation(rc *eos_io.RuntimeContext) (*InstallationStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Detecting existing OpenStack installation")

	status := &InstallationStatus{
		Installed:    false,
		Services:     []ServiceStatus{},
		Nodes:        []NodeInfo{},
		LastUpdated:  time.Now(),
		HealthStatus: "Unknown",
	}

	// Check for installation state file
	stateFile := filepath.Join(OpenStackStateDir, "installation.json")
	if data, err := os.ReadFile(stateFile); err == nil {
		if err := json.Unmarshal(data, status); err == nil {
			status.Installed = true
			logger.Debug("Found installation state file")
		}
	}

	// Detect installed services
	services := detectInstalledServices(rc)
	if len(services) > 0 {
		status.Installed = true
		status.Services = services
	}

	// Detect deployment mode
	if mode := detectDeploymentMode(rc); mode != "" {
		status.Mode = mode
	}

	// Detect OpenStack version
	if version := detectOpenStackVersion(rc); version != "" {
		status.Version = version
		status.Installed = true
	}

	// Check configuration files
	if hasConfigFiles() {
		status.Installed = true
	}

	// Assess health status
	if status.Installed {
		status.HealthStatus = assessHealthStatus(status.Services)
		
		// Gather node information
		status.Nodes = gatherNodeInfo(rc)
	}

	if !status.Installed {
		return nil, fmt.Errorf("no OpenStack installation detected")
	}

	logger.Info("Detected existing OpenStack installation",
		zap.String("version", status.Version),
		zap.String("mode", string(status.Mode)),
		zap.Int("services", len(status.Services)))

	return status, nil
}

// detectInstalledServices checks which OpenStack services are installed
func detectInstalledServices(rc *eos_io.RuntimeContext) []ServiceStatus {
	logger := otelzap.Ctx(rc.Ctx)
	
	var services []ServiceStatus

	// Service to package/process mapping
	serviceChecks := []struct {
		service Service
		process string
		packages []string
		port    int
	}{
		{
			service:  ServiceKeystone,
			process:  "apache2", // Keystone runs under Apache
			packages: []string{"keystone"},
			port:     PortKeystone,
		},
		{
			service:  ServiceGlance,
			process:  "glance-api",
			packages: []string{"glance", "glance-api"},
			port:     PortGlance,
		},
		{
			service:  ServiceNova,
			process:  "nova-api",
			packages: []string{"nova-api", "nova-conductor", "nova-compute"},
			port:     PortNovaAPI,
		},
		{
			service:  ServiceNeutron,
			process:  "neutron-server",
			packages: []string{"neutron-server", "neutron-openvswitch-agent"},
			port:     PortNeutron,
		},
		{
			service:  ServiceCinder,
			process:  "cinder-api",
			packages: []string{"cinder-api", "cinder-volume"},
			port:     PortCinder,
		},
		{
			service:  ServiceSwift,
			process:  "swift-proxy",
			packages: []string{"swift", "swift-proxy"},
			port:     PortSwift,
		},
		{
			service:  ServiceHorizon,
			process:  "",
			packages: []string{"openstack-dashboard"},
			port:     PortHorizon,
		},
		{
			service:  ServiceHeat,
			process:  "heat-api",
			packages: []string{"heat-api", "heat-engine"},
			port:     PortHeat,
		},
	}

	for _, check := range serviceChecks {
		status := ServiceStatus{
			Name:    check.service,
			Enabled: false,
			Running: false,
			Healthy: false,
		}

		// Check if packages are installed
		installed := false
		for _, pkg := range check.packages {
			if isPackageInstalled(rc, pkg) {
				installed = true
				status.Enabled = true
				break
			}
		}

		if !installed {
			continue
		}

		// Check if service is running
		if check.process != "" {
			if isProcessRunning(rc, check.process) {
				status.Running = true
			}
		}

		// Check if port is listening
		if check.port > 0 && isPortListening(check.port) {
			status.Running = true
		}

		// Get service version
		status.Version = getServiceVersion(rc, check.service)

		// Check endpoints
		status.Endpoints = getServiceEndpoints(rc, check.service)

		// Basic health check
		if status.Running && len(status.Endpoints) > 0 {
			status.Healthy = true
			status.Message = "Service is running"
		} else if status.Running {
			status.Message = "Service is running but no endpoints found"
		} else {
			status.Message = "Service is not running"
		}

		services = append(services, status)
		logger.Debug("Detected service",
			zap.String("service", string(check.service)),
			zap.Bool("running", status.Running))
	}

	return services
}

// detectDeploymentMode attempts to determine the deployment mode
func detectDeploymentMode(rc *eos_io.RuntimeContext) DeploymentMode {
	// Check for all core services - likely all-in-one
	coreServices := []string{"keystone", "glance", "nova-api", "neutron-server"}
	allPresent := true
	
	for _, svc := range coreServices {
		if !isPackageInstalled(rc, svc) {
			allPresent = false
			break
		}
	}

	if allPresent {
		// Check if compute is also present
		if isPackageInstalled(rc, "nova-compute") {
			return ModeAllInOne
		}
		return ModeController
	}

	// Check for compute-only
	if isPackageInstalled(rc, "nova-compute") && !isPackageInstalled(rc, "nova-api") {
		return ModeCompute
	}

	// Check for storage-only
	if isPackageInstalled(rc, "cinder-volume") && !isPackageInstalled(rc, "cinder-api") {
		return ModeStorage
	}

	// Check configuration files for hints
	if configMode := detectModeFromConfig(); configMode != "" {
		return configMode
	}

	return ""
}

// detectOpenStackVersion attempts to determine the installed OpenStack version
func detectOpenStackVersion(rc *eos_io.RuntimeContext) string {
	// Try various methods to detect version

	// Method 1: Check nova-common package version
	if version := getPackageVersion(rc, "nova-common"); version != "" {
		// Map package version to OpenStack release
		return mapPackageVersionToRelease(version)
	}

	// Method 2: Check keystone version via API
	if version := getKeystoneVersion(rc); version != "" {
		return version
	}

	// Method 3: Check for version file
	versionFiles := []string{
		"/etc/openstack-release",
		"/etc/openstack/release",
		filepath.Join(OpenStackStateDir, "version"),
	}

	for _, file := range versionFiles {
		if data, err := os.ReadFile(file); err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	// Method 4: Check cloud archive source
	if version := detectFromCloudArchive(); version != "" {
		return version
	}

	return ""
}

// isPackageInstalled checks if a package is installed
func isPackageInstalled(rc *eos_io.RuntimeContext, packageName string) bool {
	// Try dpkg first (Debian/Ubuntu)
	dpkgCmd := exec.CommandContext(rc.Ctx, "dpkg", "-l", packageName)
	if output, err := dpkgCmd.Output(); err == nil {
		return strings.Contains(string(output), "ii  " + packageName)
	}

	// Try rpm (RHEL/CentOS)
	rpmCmd := exec.CommandContext(rc.Ctx, "rpm", "-q", packageName)
	if rpmCmd.Run() == nil {
		return true
	}

	return false
}

// isProcessRunning checks if a process is running
func isProcessRunning(rc *eos_io.RuntimeContext, processName string) bool {
	// Use pgrep for more reliable process detection
	pgrepCmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", processName)
	return pgrepCmd.Run() == nil
}

// isPortListening checks if a port is listening
func isPortListening(port int) bool {
	// Use ss or netstat to check
	ssCmd := exec.Command("ss", "-tln")
	output, err := ssCmd.Output()
	if err != nil {
		// Try netstat as fallback
		netstatCmd := exec.Command("netstat", "-tln")
		output, err = netstatCmd.Output()
		if err != nil {
			return false
		}
	}

	portStr := fmt.Sprintf(":%d", port)
	return strings.Contains(string(output), portStr)
}

// getServiceVersion gets the version of a specific service
func getServiceVersion(rc *eos_io.RuntimeContext, service Service) string {
	// Service-specific version commands
	var cmd *exec.Cmd
	
	switch service {
	case ServiceKeystone:
		cmd = exec.CommandContext(rc.Ctx, "keystone-manage", "--version")
	case ServiceGlance:
		cmd = exec.CommandContext(rc.Ctx, "glance-manage", "version")
	case ServiceNova:
		cmd = exec.CommandContext(rc.Ctx, "nova-manage", "--version")
	case ServiceNeutron:
		cmd = exec.CommandContext(rc.Ctx, "neutron-server", "--version")
	case ServiceCinder:
		cmd = exec.CommandContext(rc.Ctx, "cinder-manage", "--version")
	default:
		return ""
	}

	if output, err := cmd.Output(); err == nil {
		// Clean up version string
		version := strings.TrimSpace(string(output))
		// Extract just the version number
		parts := strings.Fields(version)
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
		return version
	}

	return ""
}

// getServiceEndpoints retrieves endpoints for a service
func getServiceEndpoints(rc *eos_io.RuntimeContext, service Service) []string {
	// Try to get endpoints from OpenStack CLI
	sourceCmd := fmt.Sprintf(`source /etc/openstack/admin-openrc.sh 2>/dev/null && openstack endpoint list --service %s -f value -c URL 2>/dev/null`, 
		strings.ToLower(string(service)))
	
	cmd := exec.CommandContext(rc.Ctx, "bash", "-c", sourceCmd)
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		var endpoints []string
		for _, line := range lines {
			if line != "" {
				endpoints = append(endpoints, line)
			}
		}
		return endpoints
	}

	// Fallback to checking config files
	return getEndpointsFromConfig(service)
}

// hasConfigFiles checks if OpenStack configuration files exist
func hasConfigFiles() bool {
	configPaths := []string{
		"/etc/keystone/keystone.conf",
		"/etc/glance/glance-api.conf",
		"/etc/nova/nova.conf",
		"/etc/neutron/neutron.conf",
		"/etc/cinder/cinder.conf",
	}

	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

// assessHealthStatus determines overall health based on service states
func assessHealthStatus(services []ServiceStatus) string {
	if len(services) == 0 {
		return "Unknown"
	}

	totalServices := len(services)
	healthyServices := 0
	runningServices := 0

	for _, svc := range services {
		if svc.Running {
			runningServices++
		}
		if svc.Healthy {
			healthyServices++
		}
	}

	if healthyServices == totalServices {
		return "Healthy"
	} else if healthyServices > totalServices/2 {
		return "Degraded"
	} else if runningServices > 0 {
		return "Unhealthy"
	} else {
		return "Critical"
	}
}

// gatherNodeInfo collects information about OpenStack nodes
func gatherNodeInfo(rc *eos_io.RuntimeContext) []NodeInfo {
	var nodes []NodeInfo

	// Get local node info
	localNode := NodeInfo{
		Hostname:      getHostname(),
		IPAddress:     getPrimaryIP(),
		OSVersion:     getOSVersion(),
		KernelVersion: getKernelVersion(),
	}

	// Determine node role based on installed services
	if isPackageInstalled(rc, "nova-compute") {
		if isPackageInstalled(rc, "nova-api") {
			localNode.Role = ModeAllInOne
		} else {
			localNode.Role = ModeCompute
		}
	} else if isPackageInstalled(rc, "nova-api") {
		localNode.Role = ModeController
	} else if isPackageInstalled(rc, "cinder-volume") {
		localNode.Role = ModeStorage
	}

	// Get resource information
	localNode.CPUCores = getCPUCores()
	localNode.MemoryGB = getMemoryGB()
	localNode.DiskGB = getDiskGB()

	// Get services running on this node
	for _, svc := range detectInstalledServices(rc) {
		if svc.Running {
			localNode.Services = append(localNode.Services, svc.Name)
		}
	}

	nodes = append(nodes, localNode)

	// Try to get other nodes from Nova
	if otherNodes := getNovaHypervisors(rc); len(otherNodes) > 0 {
		nodes = append(nodes, otherNodes...)
	}

	return nodes
}

// Helper functions for system information

func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

func getOSVersion() string {
	// Try to read /etc/os-release
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		var name, version string
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				name = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				return name
			}
			if strings.HasPrefix(line, "NAME=") {
				name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
			}
			if strings.HasPrefix(line, "VERSION=") {
				version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
			}
		}
		if name != "" && version != "" {
			return fmt.Sprintf("%s %s", name, version)
		}
	}
	return "unknown"
}

func getKernelVersion() string {
	if output, err := exec.Command("uname", "-r").Output(); err == nil {
		return strings.TrimSpace(string(output))
	}
	return "unknown"
}

func getCPUCores() int {
	if output, err := exec.Command("nproc").Output(); err == nil {
		var cores int
		_, _ = fmt.Sscanf(string(output), "%d", &cores)
		return cores
	}
	return 0
}

func getMemoryGB() int {
	// Parse memory from /proc/meminfo
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					var memKB int64
					_, _ = fmt.Sscanf(fields[1], "%d", &memKB)
					return int(memKB / 1024 / 1024) // Convert KB to GB
				}
			}
		}
	}
	return 0
}

func getDiskGB() int {
	// Use df command to get disk space
	if output, err := exec.Command("df", "-BG", "/").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 2 {
				sizeStr := strings.TrimSuffix(fields[1], "G")
				var size int
				_, _ = fmt.Sscanf(sizeStr, "%d", &size)
				return size
			}
		}
	}
	return 0
}

// detectModeFromConfig checks configuration files for deployment mode hints
func detectModeFromConfig() DeploymentMode {
	// Check Nova configuration for compute_driver
	novaConf := "/etc/nova/nova.conf"
	if data, err := os.ReadFile(novaConf); err == nil {
		content := string(data)
		if strings.Contains(content, "compute_driver") {
			if strings.Contains(content, "[conductor]") {
				return ModeAllInOne
			}
			return ModeCompute
		}
	}

	return ""
}

// getPackageVersion gets the version of an installed package
func getPackageVersion(rc *eos_io.RuntimeContext, packageName string) string {
	// Try dpkg
	dpkgCmd := exec.CommandContext(rc.Ctx, "dpkg-query", "-W", "-f=${Version}", packageName)
	if output, err := dpkgCmd.Output(); err == nil {
		return strings.TrimSpace(string(output))
	}

	// Try rpm
	rpmCmd := exec.CommandContext(rc.Ctx, "rpm", "-q", "--queryformat", "%{VERSION}", packageName)
	if output, err := rpmCmd.Output(); err == nil {
		return strings.TrimSpace(string(output))
	}

	return ""
}

// mapPackageVersionToRelease maps package versions to OpenStack releases
func mapPackageVersionToRelease(packageVersion string) string {
	// Extract major version
	parts := strings.Split(packageVersion, ".")
	if len(parts) < 2 {
		return ""
	}

	// Map to OpenStack releases (simplified)
	releaseMap := map[string]string{
		"28.": "2024.1 (Caracal)",
		"27.": "2023.2 (Bobcat)",
		"26.": "2023.1 (Antelope)",
		"25.": "Zed",
		"24.": "Yoga",
		"23.": "Xena",
		"22.": "Wallaby",
		"21.": "Victoria",
		"20.": "Ussuri",
		"19.": "Train",
		"18.": "Stein",
		"17.": "Rocky",
		"16.": "Queens",
		"15.": "Pike",
	}

	for prefix, release := range releaseMap {
		if strings.HasPrefix(packageVersion, prefix) {
			return release
		}
	}

	return packageVersion
}

// getKeystoneVersion tries to get version via Keystone API
func getKeystoneVersion(rc *eos_io.RuntimeContext) string {
	// Check if Keystone is running
	if !isPortListening(PortKeystone) {
		return ""
	}

	// Try to get version from API
	curlCmd := exec.CommandContext(rc.Ctx, "curl", "-s", 
		fmt.Sprintf("http://localhost:%d/", PortKeystone))
	if output, err := curlCmd.Output(); err == nil {
		// Parse JSON response for version
		var response map[string]interface{}
		if err := json.Unmarshal(output, &response); err == nil {
			if version, ok := response["version"].(map[string]interface{}); ok {
				if id, ok := version["id"].(string); ok {
					return id
				}
			}
		}
	}

	return ""
}

// detectFromCloudArchive checks Ubuntu Cloud Archive for version
func detectFromCloudArchive() string {
	sourcesFile := "/etc/apt/sources.list.d/cloudarchive-*.list"
	matches, err := filepath.Glob(sourcesFile)
	if err != nil || len(matches) == 0 {
		return ""
	}

	// Extract version from filename
	for _, match := range matches {
		base := filepath.Base(match)
		if strings.HasPrefix(base, "cloudarchive-") {
			version := strings.TrimPrefix(base, "cloudarchive-")
			version = strings.TrimSuffix(version, ".list")
			return version
		}
	}

	return ""
}

// getEndpointsFromConfig reads endpoints from configuration files
func getEndpointsFromConfig(service Service) []string {
	// This would parse configuration files to find endpoint URLs
	// Simplified for this example
	return []string{}
}

// getNovaHypervisors gets information about compute nodes from Nova
func getNovaHypervisors(rc *eos_io.RuntimeContext) []NodeInfo {
	// Try to get hypervisor list from Nova
	sourceCmd := `source /etc/openstack/admin-openrc.sh 2>/dev/null && openstack hypervisor list -f json 2>/dev/null`
	
	cmd := exec.CommandContext(rc.Ctx, "bash", "-c", sourceCmd)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var hypervisors []map[string]interface{}
	if err := json.Unmarshal(output, &hypervisors); err != nil {
		return nil
	}

	var nodes []NodeInfo
	for _, h := range hypervisors {
		node := NodeInfo{
			Role: ModeCompute,
		}

		if name, ok := h["Hypervisor Hostname"].(string); ok {
			node.Hostname = name
		}
		if vcpus, ok := h["vCPUs"].(float64); ok {
			node.CPUCores = int(vcpus)
		}
		if mem, ok := h["Memory MB"].(float64); ok {
			node.MemoryGB = int(mem / 1024)
		}
		if disk, ok := h["Local GB"].(float64); ok {
			node.DiskGB = int(disk)
		}

		nodes = append(nodes, node)
	}

	return nodes
}