// pkg/kvm/inventory.go
// VM inventory management with drift detection

package kvm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"libvirt.org/go/libvirt"
)


// hostQEMUVersionCache caches the host QEMU version to avoid repeated expensive checks
var hostQEMUVersionCache string

// ListVMs returns all VMs with their information
func ListVMs(ctx context.Context) ([]VMInfo, error) {
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
		vm, err := getVMInfo(&domain, hostQEMUVersion)
		if err != nil {
			// Log error but continue with other VMs
			continue
		}
		vms = append(vms, vm)
		domain.Free()
	}

	return vms, nil
}

// getVMInfo extracts comprehensive information from a domain
func getVMInfo(domain *libvirt.Domain, hostQEMUVersion string) (VMInfo, error) {
	vm := VMInfo{}

	// Get basic info
	name, err := domain.GetName()
	if err != nil {
		return vm, err
	}
	vm.Name = name

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

		// Get memory usage (works without guest agent)
		vm.MemoryUsageMB = getVMMemoryUsage(domain)

		// Get OS info, Consul status, and updates status if guest agent is available
		if vm.GuestAgentOK {
			vm.OSInfo = getVMOSInfo(domain)
			vm.ConsulAgent = checkConsulAgent(domain)
			vm.UpdatesNeeded = checkUpdatesNeeded(domain)
			vm.DiskUsageGB = getVMDiskUsage(domain)
			vm.CPUUsagePercent = getVMLoadAverage(domain) // Load average, not CPU%
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
	vms, err := ListVMs(ctx)
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
func checkConsulAgent(domain *libvirt.Domain) bool {
	// Execute command to check if consul service is running
	// Using systemctl status consul
	cmd := `{"execute":"guest-exec","arguments":{"path":"/usr/bin/systemctl","arg":["is-active","consul"],"capture-output":true}}`
	result, err := domain.QemuAgentCommand(
		cmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		return false
	}

	// Parse response to get PID
	var execResponse struct {
		Return struct {
			PID int `json:"pid"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(result), &execResponse); err != nil {
		return false
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
		return false
	}

	// Check if command exited successfully (exit code 0 means service is active)
	return strings.Contains(statusResult, `"exited":true`) && strings.Contains(statusResult, `"exitcode":0`)
}

// checkUpdatesNeeded checks if OS updates are available via guest agent
func checkUpdatesNeeded(domain *libvirt.Domain) bool {
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
					return true
				}
				// Exit code 0 means no updates
				if strings.Contains(statusResult, `"exitcode":0`) {
					return false
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
					return len(lines) > 2 // More than header + blank line means updates available
				}
			}
		}
	}

	// Default to unknown/false if we can't determine
	return false
}

// getVMDiskSize gets the total allocated disk size in GB
func getVMDiskSize(domain *libvirt.Domain) int {
	// Get XML description to find disk paths
	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return 0
	}

	// Parse disk paths from XML - try multiple formats
	// Format 1: <source file='/path/to/disk.qcow2'/>
	diskRegex := regexp.MustCompile(`<source file=['"]([^'"]+)['"]`)
	matches := diskRegex.FindAllStringSubmatch(xmlDesc, -1)

	// Format 2: <source dev='/dev/...'/>
	if len(matches) == 0 {
		diskRegex = regexp.MustCompile(`<source dev=['"]([^'"]+)['"]`)
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
		// qemu-img might not work for block devices, try different approach
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

// getVMDiskUsage gets the used disk space in GB via guest agent
func getVMDiskUsage(domain *libvirt.Domain) int {
	// Use guest-get-fsinfo to get filesystem info
	result, err := domain.QemuAgentCommand(
		`{"execute":"guest-get-fsinfo"}`,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		return 0
	}

	// Parse response to find root filesystem
	var response struct {
		Return []struct {
			Name       string `json:"name"`
			Mountpoint string `json:"mountpoint"`
			Type       string `json:"type"`
			UsedBytes  int64  `json:"used-bytes"`
			TotalBytes int64  `json:"total-bytes"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(result), &response); err != nil {
		return 0
	}

	// Find root filesystem and return used space
	for _, fs := range response.Return {
		if fs.Mountpoint == "/" {
			return int(fs.UsedBytes / (1024 * 1024 * 1024))
		}
	}

	return 0
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

// getVMMemoryUsage gets current memory usage in MB
func getVMMemoryUsage(domain *libvirt.Domain) int {
	// Get memory stats
	memStats, err := domain.MemoryStats(11, 0) // 11 = all stats
	if err != nil {
		return 0
	}

	// Look for actual memory usage
	var actualMB int64
	for _, stat := range memStats {
		// VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON = 6
		// VIR_DOMAIN_MEMORY_STAT_RSS = 5
		if stat.Tag == 5 { // RSS = Resident Set Size (actual usage)
			actualMB = int64(stat.Val / 1024) // Convert KB to MB
			break
		}
	}

	return int(actualMB)
}
