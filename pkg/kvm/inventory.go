// pkg/kvm/inventory.go
// VM inventory management with drift detection

package kvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

// hostQEMUVersionCache caches the host QEMU version to avoid repeated expensive checks
var hostQEMUVersionCache string

// ListVMs returns all VMs with their information
func ListVMs(rc *eos_io.RuntimeContext) ([]VMInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer conn.Close()

	domains, err := conn.ListAllDomains(0)
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	// Get host QEMU version once (expensive operation)
	hostQEMUVersion := getHostQEMUVersion()

	var vms []VMInfo
	for _, domain := range domains {
		vm, err := getVMInfo(&domain, hostQEMUVersion, logger)
		if err != nil {
			// Log error but continue with other VMs
			logger.Warn("Failed to get VM info", zap.Error(err))
			continue
		}
		vms = append(vms, vm)
		domain.Free()
	}

	return vms, nil
}

// getVMInfo extracts comprehensive information from a domain
func getVMInfo(domain *libvirt.Domain, hostQEMUVersion string, logger otelzap.LoggerWithCtx) (VMInfo, error) {
	vm := VMInfo{}

	// Get basic info
	name, err := domain.GetName()
	if err != nil {
		return vm, err
	}
	vm.Name = name

	logger.Debug("Processing VM", zap.String("vm_name", name))

	uuid, err := domain.GetUUIDString()
	if err == nil {
		vm.UUID = uuid
	}

	// Get state
	state, _, err := domain.GetState()
	if err != nil {
		return vm, err
	}
	vm.State = stateToString(state)

	// Get vCPU and memory info
	info, err := domain.GetInfo()
	if err == nil {
		vm.VCPUs = int(info.NrVirtCpu)
		vm.MemoryMB = int(info.Memory / 1024) // Convert KB to MB
	}

	// Get disk size (works for all VMs)
	vm.DiskSizeGB = getVMDiskSize(domain)

	// For running VMs, get additional info
	if state == libvirt.DOMAIN_RUNNING {
		vm.QEMUVersion = getVMQEMUVersion(domain)
		vm.HostQEMUVersion = hostQEMUVersion
		vm.DriftDetected = (vm.QEMUVersion != "" && vm.HostQEMUVersion != "" &&
			vm.QEMUVersion != vm.HostQEMUVersion)

		vm.UptimeDays = getVMUptime(domain)
		vm.GuestAgentOK = checkGuestAgent(domain)
		vm.NetworkIPs = getVMIPs(domain)

		// Get memory usage with balloon statistics
		usedMB, availableMB, balloonMB := getVMMemoryUsage(domain, logger)
		vm.MemoryUsageMB = usedMB
		logger.Debug("Memory stats",
			zap.String("vm", name),
			zap.Int("used_mb", usedMB),
			zap.Int("available_mb", availableMB),
			zap.Int("balloon_mb", balloonMB),
			zap.Int("allocated_mb", vm.MemoryMB))

		// Get CPU usage percentage (requires 1-second sampling)
		vm.CPUUsagePercent = getVMCPUUsage(domain, logger)

		// Get OS info, Consul status, and updates status if guest agent is available
		if vm.GuestAgentOK {
			vm.OSInfo = getVMOSInfo(domain)
			vm.ConsulAgent = checkConsulAgent(domain)
			vm.UpdatesNeeded = checkUpdatesNeeded(domain)

			// Get disk usage percentage
			usedGB, totalGB := getVMDiskUsagePercent(domain, logger)
			vm.DiskUsageGB = usedGB
			vm.DiskTotalGB = totalGB
			logger.Debug("Disk usage",
				zap.String("vm", name),
				zap.Int("used_gb", usedGB),
				zap.Int("total_gb", totalGB),
				zap.Int("allocated_gb", vm.DiskSizeGB))
		}
	}

	return vm, nil
}

// stateToString converts libvirt state to human-readable string
func stateToString(state libvirt.DomainState) string {
	switch state {
	case libvirt.DOMAIN_NOSTATE:
		return "nostate"
	case libvirt.DOMAIN_RUNNING:
		return "running"
	case libvirt.DOMAIN_BLOCKED:
		return "blocked"
	case libvirt.DOMAIN_PAUSED:
		return "paused"
	case libvirt.DOMAIN_SHUTDOWN:
		return "shutdown"
	case libvirt.DOMAIN_SHUTOFF:
		return "shutoff"
	case libvirt.DOMAIN_CRASHED:
		return "crashed"
	case libvirt.DOMAIN_PMSUSPENDED:
		return "pmsuspended"
	default:
		return "unknown"
	}
}

// getVMQEMUVersion extracts QEMU version from running VM process
func getVMQEMUVersion(domain *libvirt.Domain) string {
	// Get domain ID (PID is related to domain ID)
	id, err := domain.GetID()
	if err != nil {
		return ""
	}

	// Try to find QEMU process and extract version
	// This is system-specific and may need adjustment
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Look for qemu process with this domain
	name, _ := domain.GetName()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "qemu-system") && strings.Contains(line, name) {
			// Extract version from command line
			version := extractQEMUVersionFromCmdline(line)
			if version != "" {
				return version
			}
		}
	}

	// Fallback: try to get from /proc if we have the ID
	if id > 0 {
		// This is a simplified approach; actual PID mapping may differ
		return getQEMUVersionFromProc(uint(id))
	}

	return ""
}

// extractQEMUVersionFromCmdline attempts to extract QEMU version from command line
func extractQEMUVersionFromCmdline(cmdline string) string {
	// Try to find version in the qemu-system-x86_64 path or args
	// Example: /usr/bin/qemu-system-x86_64 -version might appear

	// Check if we can execute the binary to get version
	if strings.Contains(cmdline, "qemu-system-x86_64") {
		// Extract the path
		re := regexp.MustCompile(`(/[^\s]+/qemu-system-x86_64)`)
		matches := re.FindStringSubmatch(cmdline)
		if len(matches) > 1 {
			cmd := exec.Command(matches[1], "--version")
			output, err := cmd.Output()
			if err == nil {
				return parseQEMUVersion(string(output))
			}
		}
	}

	return ""
}

// getQEMUVersionFromProc reads QEMU version from /proc filesystem
func getQEMUVersionFromProc(pid uint) string {
	// Read /proc/<pid>/exe symlink
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	realPath, err := os.Readlink(exePath)
	if err != nil {
		return ""
	}

	// Execute the binary with --version
	cmd := exec.Command(realPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return parseQEMUVersion(string(output))
}

// getHostQEMUVersion gets the installed QEMU version on the host
func getHostQEMUVersion() string {
	// Return cached version if available
	if hostQEMUVersionCache != "" {
		return hostQEMUVersionCache
	}

	// Try common QEMU binary locations
	binaries := []string{
		"/usr/bin/qemu-system-x86_64",
		"/usr/local/bin/qemu-system-x86_64",
		"qemu-system-x86_64", // PATH lookup
	}

	for _, binary := range binaries {
		cmd := exec.Command(binary, "--version")
		output, err := cmd.Output()
		if err == nil {
			version := parseQEMUVersion(string(output))
			if version != "" {
				hostQEMUVersionCache = version
				return version
			}
		}
	}

	return "unknown"
}

// parseQEMUVersion extracts version number from QEMU version output
func parseQEMUVersion(output string) string {
	// Example output: "QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1)"
	// We want to extract "8.2.2"

	re := regexp.MustCompile(`version\s+(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}

	// Alternative format: "qemu-system-x86_64 version 8.2.2"
	re = regexp.MustCompile(`qemu-system-x86_64.*?(\d+\.\d+\.\d+)`)
	matches = re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// getVMUptime calculates VM uptime in days
func getVMUptime(domain *libvirt.Domain) int {
	// Get domain stats including CPU time
	stats, err := domain.GetInfo()
	if err != nil {
		return 0
	}

	// CPU time is in nanoseconds, convert to days
	// Note: This is CPU time, not wall-clock uptime
	// For accurate uptime, we'd need to track boot time separately
	uptimeNanos := stats.CpuTime
	uptimeDays := int(uptimeNanos / (1000000000 * 60 * 60 * 24))

	return uptimeDays
}

// checkGuestAgent checks if QEMU guest agent is responsive
func checkGuestAgent(domain *libvirt.Domain) bool {
	// Check if domain is running first (guest agent only works on running VMs)
	state, _, err := domain.GetState()
	if err != nil || state != libvirt.DOMAIN_RUNNING {
		return false
	}

	// Try to ping the guest agent with a short timeout
	// The guest-ping command should return immediately if the agent is responsive
	// Use explicit type cast for libvirt constant (required for Go bindings)
	result, err := domain.QemuAgentCommand(
		`{"execute":"guest-ping"}`,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		// Guest agent not available or not responsive
		return false
	}

	// Check if we got a valid response (should be {"return":{}})
	return result != "" && (result == `{"return":{}}` || result == `{"return": {}}`)
}

// getVMIPs retrieves network IP addresses for the VM with retry logic
func getVMIPs(domain *libvirt.Domain) []string {
	var ips []string

	// Get the XML description and parse network interfaces
	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return ips
	}

	// Parse MAC addresses from XML - only get the first one (primary interface)
	macRegex := regexp.MustCompile(`<mac address='([^']+)'`)
	macs := macRegex.FindAllStringSubmatch(xmlDesc, -1)

	if len(macs) == 0 {
		return ips
	}

	// Try primary interface first (first MAC in XML)
	primaryMAC := macs[0][1]

	// Retry up to 3 times with 1-second delay for newly started VMs
	for attempt := 0; attempt < 3; attempt++ {
		ip := getIPFromMAC(primaryMAC)
		if ip != "" {
			ips = append(ips, ip)
			break
		}
		if attempt < 2 {
			time.Sleep(1 * time.Second)
		}
	}

	// Try other interfaces if primary didn't work
	if len(ips) == 0 && len(macs) > 1 {
		for i := 1; i < len(macs); i++ {
			if len(macs[i]) > 1 {
				ip := getIPFromMAC(macs[i][1])
				if ip != "" {
					ips = append(ips, ip)
					break // Stop after finding first IP
				}
			}
		}
	}

	return ips
}

// getIPFromMAC attempts to find IP address for a given MAC address
func getIPFromMAC(mac string) string {
	// SECURITY P0 #3: Validate MAC address format to prevent command injection
	macRegex := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	if !macRegex.MatchString(mac) {
		return "" // Invalid MAC format, refuse to process
	}

	// Try ARP cache first - use arp command directly, parse output in Go
	cmd := exec.Command("arp", "-an")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		// Parse ARP output safely in Go instead of shell pipeline
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(mac)) {
				// Extract IP from format: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff
				ipRegex := regexp.MustCompile(`\(([0-9.]+)\)`)
				if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
					return matches[1]
				}
			}
		}
	}

	// Try virsh net-dhcp-leases for default network
	cmd = exec.Command("virsh", "net-dhcp-leases", "default")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(mac)) {
				// Parse IP from lease line
				// Format: Expiry Time          MAC address        Protocol  IP address                Hostname        Client ID or DUID
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					// IP is usually in field index 4
					ipPort := fields[4]
					// Remove /prefix if present
					parts := strings.Split(ipPort, "/")
					if len(parts) > 0 {
						return parts[0]
					}
				}
			}
		}
	}

	return ""
}

// FilterVMsWithDrift returns only VMs with QEMU version drift
func FilterVMsWithDrift(vms []VMInfo) []VMInfo {
	filtered := make([]VMInfo, 0)
	for _, vm := range vms {
		if vm.DriftDetected {
			filtered = append(filtered, vm)
		}
	}
	return filtered
}

// GetVMByName finds a specific VM by name
func GetVMByName(ctx context.Context, name string) (*VMInfo, error) {
	// Create RuntimeContext for ListVMs
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	vms, err := ListVMs(rc)
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		if vm.Name == name {
			return &vm, nil
		}
	}

	return nil, fmt.Errorf("VM not found: %s", name)
}

// getVMOSInfo retrieves operating system information via guest agent
func getVMOSInfo(domain *libvirt.Domain) string {
	// Use guest-get-osinfo command to get OS details
	result, err := domain.QemuAgentCommand(
		`{"execute":"guest-get-osinfo"}`,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		return "Unknown"
	}

	// Parse JSON response
	// Example: {"return":{"name":"CentOS Stream","id":"centos","version":"9","version-id":"9"}}
	var response struct {
		Return struct {
			Name      string `json:"name"`
			ID        string `json:"id"`
			Version   string `json:"version"`
			VersionID string `json:"version-id"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(result), &response); err != nil {
		return "Unknown"
	}

	// Format OS info nicely
	osInfo := response.Return.Name
	if response.Return.Version != "" {
		osInfo += " " + response.Return.Version
	}

	return osInfo
}

// checkConsulAgent checks if Consul agent is installed and running via guest agent
func checkConsulAgent(domain *libvirt.Domain) string {
	// Execute command to check if consul service is running
	// Using systemctl status consul
	cmd := `{"execute":"guest-exec","arguments":{"path":"/usr/bin/systemctl","arg":["is-active","consul"],"capture-output":true}}`
	result, err := domain.QemuAgentCommand(
		cmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		// Check if guest-exec is disabled
		if strings.Contains(err.Error(), "has been disabled") {
			return "DISABLED"
		}
		return "N/A"
	}

	// Parse response to get PID
	var execResponse struct {
		Return struct {
			PID int `json:"pid"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(result), &execResponse); err != nil {
		return "N/A"
	}

	// Wait a moment for command to complete, then check status
	time.Sleep(100 * time.Millisecond)

	// Get command status
	statusCmd := fmt.Sprintf(`{"execute":"guest-exec-status","arguments":{"pid":%d}}`, execResponse.Return.PID)
	statusResult, err := domain.QemuAgentCommand(
		statusCmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		return "N/A"
	}

	// Check if command exited successfully (exit code 0 means service is active)
	if strings.Contains(statusResult, `"exited":true`) && strings.Contains(statusResult, `"exitcode":0`) {
		return "YES"
	}
	return "NO"
}

// checkUpdatesNeeded checks if OS updates are available via guest agent
func checkUpdatesNeeded(domain *libvirt.Domain) string {
	// Execute command to check for updates
	// For CentOS/RHEL: dnf check-update (exit code 100 means updates available)
	// For Ubuntu/Debian: apt list --upgradable (check output)

	// Try dnf first (CentOS/RHEL/Rocky)
	cmd := `{"execute":"guest-exec","arguments":{"path":"/usr/bin/dnf","arg":["check-update","-q"],"capture-output":true}}`
	result, err := domain.QemuAgentCommand(
		cmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)

	// Check if guest-exec is disabled
	if err != nil && strings.Contains(err.Error(), "has been disabled") {
		return "DISABLED"
	}

	if err == nil {
		var execResponse struct {
			Return struct {
				PID int `json:"pid"`
			} `json:"return"`
		}

		if err := json.Unmarshal([]byte(result), &execResponse); err == nil {
			time.Sleep(500 * time.Millisecond) // Wait longer for package check

			statusCmd := fmt.Sprintf(`{"execute":"guest-exec-status","arguments":{"pid":%d}}`, execResponse.Return.PID)
			statusResult, err := domain.QemuAgentCommand(
				statusCmd,
				libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
				0,
			)
			if err == nil {
				// dnf check-update returns 100 if updates are available
				if strings.Contains(statusResult, `"exitcode":100`) {
					return "YES"
				}
				// Exit code 0 means no updates
				if strings.Contains(statusResult, `"exitcode":0`) {
					return "NO"
				}
			}
		}
	}

	// Try apt (Ubuntu/Debian) if dnf wasn't found
	cmd = `{"execute":"guest-exec","arguments":{"path":"/usr/bin/apt","arg":["list","--upgradable"],"capture-output":true}}`
	result, err = domain.QemuAgentCommand(
		cmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)

	// Check if guest-exec is disabled (apt attempt)
	if err != nil && strings.Contains(err.Error(), "has been disabled") {
		return "DISABLED"
	}

	if err == nil {
		var execResponse struct {
			Return struct {
				PID int `json:"pid"`
			} `json:"return"`
		}

		if err := json.Unmarshal([]byte(result), &execResponse); err == nil {
			time.Sleep(500 * time.Millisecond)

			statusCmd := fmt.Sprintf(`{"execute":"guest-exec-status","arguments":{"pid":%d}}`, execResponse.Return.PID)
			statusResult, err := domain.QemuAgentCommand(
				statusCmd,
				libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
				0,
			)
			if err == nil && strings.Contains(statusResult, `"exited":true`) {
				// Check if output contains upgradable packages (more than just the header line)
				var statusResponse struct {
					Return struct {
						OutData string `json:"out-data"`
					} `json:"return"`
				}
				if err := json.Unmarshal([]byte(statusResult), &statusResponse); err == nil {
					// If there are upgradable packages, output will have more than just the "Listing..." header
					lines := strings.Split(statusResponse.Return.OutData, "\n")
					if len(lines) > 2 { // More than header + blank line means updates available
						return "YES"
					}
					return "NO"
				}
			}
		}
	}

	// Default to unknown if we can't determine
	return "N/A"
}

// getVMDiskSize gets the total allocated disk size in GB
func getVMDiskSize(domain *libvirt.Domain) int {
	// Get XML description to find disk paths and device names
	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return 0
	}

	// For running VMs, use libvirt's GetBlockInfo (works without exclusive lock)
	// For stopped VMs, use qemu-img as fallback
	state, _, err := domain.GetState()
	if err == nil && state == libvirt.DOMAIN_RUNNING {
		// Extract target device name (usually vda, sda, etc.)
		// Look for: <target dev='vda' bus='virtio'/>
		targetRegex := regexp.MustCompile(`<disk[^>]*type=['"]file['"][^>]*device=['"]disk['"][^>]*>[\s\S]*?<target dev=['"]([^'"]+)['"]`)
		targetMatches := targetRegex.FindStringSubmatch(xmlDesc)

		if len(targetMatches) > 1 {
			targetDev := targetMatches[1]

			// Use GetBlockInfo to get disk capacity (works for running VMs)
			blockInfo, err := domain.GetBlockInfo(targetDev, 0)
			if err == nil {
				// Capacity is in bytes, convert to GB
				sizeGB := int(blockInfo.Capacity / (1024 * 1024 * 1024))
				return sizeGB
			}
		}
	}

	// Fallback: For stopped VMs or if BlockInfo fails, use qemu-img
	// Look for disk type='file' entries (most common for VMs)
	diskTypeRegex := regexp.MustCompile(`<disk[^>]*type=['"]file['"][^>]*device=['"]disk['"][\s\S]*?<source file=['"]([^'"]+)['"]`)
	matches := diskTypeRegex.FindAllStringSubmatch(xmlDesc, -1)

	// Try simpler pattern if above doesn't match
	if len(matches) == 0 {
		diskRegex := regexp.MustCompile(`<source file=['"]([^'"]+)['"]`)
		matches = diskRegex.FindAllStringSubmatch(xmlDesc, -1)
	}

	// Try block devices as last resort
	if len(matches) == 0 {
		diskRegex := regexp.MustCompile(`<source dev=['"]([^'"]+)['"]`)
		matches = diskRegex.FindAllStringSubmatch(xmlDesc, -1)
	}

	if len(matches) == 0 {
		return 0
	}

	// Get size of first disk (usually the main OS disk)
	diskPath := matches[0][1]

	// Use qemu-img info to get virtual size
	cmd := exec.Command("qemu-img", "info", "--output=json", diskPath)
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Parse JSON output
	var info struct {
		VirtualSize int64 `json:"virtual-size"`
	}

	if err := json.Unmarshal(output, &info); err != nil {
		return 0
	}

	// Convert bytes to GB
	sizeGB := int(info.VirtualSize / (1024 * 1024 * 1024))
	return sizeGB
}

// getVMLoadAverage gets the 1-minute load average via guest agent
func getVMLoadAverage(domain *libvirt.Domain) float64 {
	// Execute uptime command to get load average
	cmd := `{"execute":"guest-exec","arguments":{"path":"/usr/bin/uptime","capture-output":true}}`
	result, err := domain.QemuAgentCommand(
		cmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		// Check if guest-exec is disabled (will show as just VCPU count without load average)
		if strings.Contains(err.Error(), "has been disabled") {
			return 0.0
		}
		return 0.0
	}

	var execResponse struct {
		Return struct {
			PID int `json:"pid"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(result), &execResponse); err != nil {
		return 0.0
	}

	time.Sleep(100 * time.Millisecond)

	statusCmd := fmt.Sprintf(`{"execute":"guest-exec-status","arguments":{"pid":%d}}`, execResponse.Return.PID)
	statusResult, err := domain.QemuAgentCommand(
		statusCmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		return 0.0
	}

	// Parse uptime output to extract load average
	var statusResponse struct {
		Return struct {
			OutData string `json:"out-data"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(statusResult), &statusResponse); err != nil {
		return 0.0
	}

	// Parse load average from uptime output
	// Example: " 14:23:45 up 2 days,  3:45,  2 users,  load average: 0.52, 0.58, 0.59"
	output := statusResponse.Return.OutData
	loadAvgRegex := regexp.MustCompile(`load average:\s+([0-9.]+)`)
	matches := loadAvgRegex.FindStringSubmatch(output)
	if len(matches) > 1 {
		var loadAvg float64
		if _, err := fmt.Sscanf(matches[1], "%f", &loadAvg); err == nil {
			return loadAvg
		}
	}

	return 0.0
}

// getVMMemoryUsage gets current memory usage in MB using balloon statistics
// Returns: usedMB, availableMB, actualBalloonMB
func getVMMemoryUsage(domain *libvirt.Domain, logger otelzap.LoggerWithCtx) (int, int, int) {
	// Enable balloon statistics collection (1 second period)
	// This is required to get Tag 7 (available) and Tag 4 (unused)
	// Using numeric value 1 for DOMAIN_AFFECT_LIVE (not available on macOS)
	if err := domain.SetMemoryStatsPeriod(1, 1); err != nil {
		logger.Debug("Failed to set memory stats period", zap.Error(err))
	}

	// Small delay to allow balloon driver to collect stats
	time.Sleep(100 * time.Millisecond)

	// Get memory stats - request up to 20 stats
	memStats, err := domain.MemoryStats(20, 0)
	if err != nil {
		logger.Debug("Failed to get memory stats", zap.Error(err))
		return 0, 0, 0
	}

	// Memory stat tags from libvirt:
	// Tag 0 (swap_in)     = Amount of memory swapped in (KB)
	// Tag 1 (swap_out)    = Amount of memory swapped out (KB)
	// Tag 2 (major_fault) = Number of major page faults
	// Tag 3 (minor_fault) = Number of minor page faults
	// Tag 4 (unused)      = Amount of memory left unused by system (KB) - requires balloon
	// Tag 5 (available)   = Amount of usable memory (KB) - requires balloon
	// Tag 6 (actual_balloon) = Current balloon size (KB) - memory given to guest
	// Tag 7 (rss)         = Resident Set Size of QEMU process (KB) - hypervisor view
	// Tag 8 (usable)      = Amount of memory that can be reclaimed (KB)
	// Tag 9 (last_update) = Timestamp of last update

	var unused, available, actualBalloon, rss int64

	logger.Debug("Raw memory stats retrieved",
		zap.Int("stat_count", len(memStats)))

	for _, stat := range memStats {
		logger.Debug("Memory stat",
			zap.Int32("tag", stat.Tag),
			zap.Uint64("value_kb", stat.Val))

		switch stat.Tag {
		case 4: // unused - memory left unused by guest
			unused = int64(stat.Val)
		case 5: // available - total memory available to guest
			available = int64(stat.Val)
		case 6: // actual_balloon - current balloon size
			actualBalloon = int64(stat.Val)
		case 7: // rss - QEMU process size (hypervisor view)
			rss = int64(stat.Val)
		}
	}

	// Calculate memory usage:
	// If we have balloon stats (unused + available), use them for guest OS view
	// Otherwise fall back to RSS (hypervisor view, less accurate)
	usedMB := 0
	availableMB := 0
	actualBalloonMB := int(actualBalloon / 1024)

	if available > 0 && unused > 0 {
		// Best case: We have balloon driver stats from guest OS
		// available = total memory guest can use
		// unused = memory guest is not using
		// used = available - unused
		usedMB = int((available - unused) / 1024)
		availableMB = int(available / 1024)
		logger.Debug("Using balloon stats (guest OS view)",
			zap.Int("used_mb", usedMB),
			zap.Int("available_mb", availableMB))
	} else if actualBalloon > 0 && rss > 0 {
		// Fallback: Use RSS as approximation
		// Note: This is hypervisor view and includes QEMU overhead
		// It's not accurate for guest OS usage but better than nothing
		usedMB = int(rss / 1024)
		availableMB = int(actualBalloon / 1024)
		logger.Debug("Using RSS (hypervisor view, approximate)",
			zap.Int("rss_mb", usedMB),
			zap.Int("balloon_mb", availableMB))
	}

	return usedMB, availableMB, actualBalloonMB
}

// getVMDiskUsagePercent gets disk usage percentage via guest agent
// Returns: usedGB, totalGB (both 0 if unavailable)
func getVMDiskUsagePercent(domain *libvirt.Domain, logger otelzap.LoggerWithCtx) (int, int) {
	// Try to get filesystem info via guest agent
	// This requires guest-exec to be enabled
	cmd := `{"execute":"guest-get-fsinfo"}`
	result, err := domain.QemuAgentCommand(
		cmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)

	if err != nil {
		// Check if guest-exec/commands are disabled
		if strings.Contains(err.Error(), "has been disabled") || strings.Contains(err.Error(), "not supported") {
			logger.Debug("Guest agent filesystem commands disabled")
			return 0, 0
		}
		logger.Debug("Failed to get filesystem info", zap.Error(err))
		return 0, 0
	}

	// Parse filesystem info response
	var fsInfoResponse struct {
		Return []struct {
			Name       string `json:"name"`
			Mountpoint string `json:"mountpoint"`
			Type       string `json:"type"`
			UsedBytes  uint64 `json:"used-bytes"`
			TotalBytes uint64 `json:"total-bytes"`
			Disk       []struct {
				Target string `json:"target"`
			} `json:"disk"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(result), &fsInfoResponse); err != nil {
		logger.Debug("Failed to parse filesystem info", zap.Error(err))
		return 0, 0
	}

	// Find root filesystem (mountpoint = "/")
	for _, fs := range fsInfoResponse.Return {
		logger.Debug("Filesystem info",
			zap.String("mountpoint", fs.Mountpoint),
			zap.String("type", fs.Type),
			zap.Uint64("used_bytes", fs.UsedBytes),
			zap.Uint64("total_bytes", fs.TotalBytes))

		if fs.Mountpoint == "/" && fs.TotalBytes > 0 {
			usedGB := int(fs.UsedBytes / (1024 * 1024 * 1024))
			totalGB := int(fs.TotalBytes / (1024 * 1024 * 1024))
			logger.Debug("Root filesystem usage",
				zap.Int("used_gb", usedGB),
				zap.Int("total_gb", totalGB))
			return usedGB, totalGB
		}
	}

	// Fallback: Try using guest-exec with df command
	// This is less reliable but works if guest-get-fsinfo is not available
	dfCmd := `{"execute":"guest-exec","arguments":{"path":"/bin/df","arg":["-B","1","/"],"capture-output":true}}`
	result, err = domain.QemuAgentCommand(
		dfCmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)

	if err != nil {
		if strings.Contains(err.Error(), "has been disabled") {
			logger.Debug("Guest-exec disabled, cannot get disk usage")
		}
		return 0, 0
	}

	// Parse guest-exec response to get PID
	var execResponse struct {
		Return struct {
			PID int `json:"pid"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(result), &execResponse); err != nil {
		return 0, 0
	}

	// Wait for command to complete
	time.Sleep(200 * time.Millisecond)

	// Get command output
	statusCmd := fmt.Sprintf(`{"execute":"guest-exec-status","arguments":{"pid":%d}}`, execResponse.Return.PID)
	statusResult, err := domain.QemuAgentCommand(
		statusCmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)

	if err != nil {
		return 0, 0
	}

	// Parse df output
	var statusResponse struct {
		Return struct {
			Exited   bool   `json:"exited"`
			ExitCode int    `json:"exitcode"`
			OutData  string `json:"out-data"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(statusResult), &statusResponse); err != nil {
		return 0, 0
	}

	if !statusResponse.Return.Exited || statusResponse.Return.ExitCode != 0 {
		return 0, 0
	}

	// Parse df output (base64 encoded)
	dfOutput, err := base64.StdEncoding.DecodeString(statusResponse.Return.OutData)
	if err != nil {
		return 0, 0
	}

	// Example df output:
	// Filesystem     1B-blocks      Used Available Use% Mounted on
	// /dev/vda1      42945478656 8589934592 ...    20%  /
	lines := strings.Split(string(dfOutput), "\n")
	if len(lines) < 2 {
		return 0, 0
	}

	// Parse the data line (skip header)
	fields := strings.Fields(lines[1])
	if len(fields) >= 3 {
		var totalBytes, usedBytes uint64
		fmt.Sscanf(fields[1], "%d", &totalBytes)
		fmt.Sscanf(fields[2], "%d", &usedBytes)

		if totalBytes > 0 {
			usedGB := int(usedBytes / (1024 * 1024 * 1024))
			totalGB := int(totalBytes / (1024 * 1024 * 1024))
			logger.Debug("Disk usage from df",
				zap.Int("used_gb", usedGB),
				zap.Int("total_gb", totalGB))
			return usedGB, totalGB
		}
	}

	return 0, 0
}

// getVMCPUUsage gets CPU usage percentage by sampling CPU time
// Returns: cpuPercent (0.0 if unavailable)
func getVMCPUUsage(domain *libvirt.Domain, logger otelzap.LoggerWithCtx) float64 {
	// Get domain info for CPU time
	// We need to sample twice to calculate CPU percentage

	// First sample - get CPU time
	info1, err := domain.GetInfo()
	if err != nil {
		logger.Debug("Failed to get domain info for CPU stats", zap.Error(err))
		return 0.0
	}
	cpuTime1 := info1.CpuTime

	// Wait 1 second
	time.Sleep(1 * time.Second)

	// Second sample
	info2, err := domain.GetInfo()
	if err != nil {
		logger.Debug("Failed to get second domain info sample", zap.Error(err))
		return 0.0
	}
	cpuTime2 := info2.CpuTime

	vcpuCount := uint64(info2.NrVirtCpu)

	if cpuTime1 == 0 || cpuTime2 == 0 || vcpuCount == 0 {
		logger.Debug("Missing CPU time or VCPU count",
			zap.Uint64("cpu_time1", cpuTime1),
			zap.Uint64("cpu_time2", cpuTime2),
			zap.Uint64("vcpu_count", vcpuCount))
		return 0.0
	}

	// Calculate CPU percentage
	// CpuTime is cumulative CPU time in nanoseconds
	// Delta is how much CPU time was used in the 1-second interval
	// Formula: (cpuTimeDelta / wallTimeDelta) * 100
	//
	// cpuTimeDelta is in nanoseconds
	// wallTimeDelta = 1 second = 1,000,000,000 nanoseconds
	cpuTimeDelta := float64(cpuTime2 - cpuTime1)
	wallTimeDelta := 1000000000.0 // 1 second in nanoseconds

	// CPU percentage (can exceed 100% with multiple vCPUs)
	cpuPercent := (cpuTimeDelta / wallTimeDelta) * 100.0

	logger.Debug("CPU usage calculated",
		zap.Uint64("cpu_time_delta_ns", cpuTime2-cpuTime1),
		zap.Float64("cpu_percent", cpuPercent),
		zap.Uint64("vcpu_count", vcpuCount))

	return cpuPercent
}
