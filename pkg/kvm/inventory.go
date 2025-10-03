// +build libvirt

// pkg/kvm/inventory.go
// VM inventory management with drift detection

package kvm

import (
	"context"
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

	// For running VMs, get additional info
	if state == libvirt.DOMAIN_RUNNING {
		vm.QEMUVersion = getVMQEMUVersion(domain)
		vm.HostQEMUVersion = hostQEMUVersion
		vm.DriftDetected = (vm.QEMUVersion != "" && vm.HostQEMUVersion != "" &&
			vm.QEMUVersion != vm.HostQEMUVersion)

		vm.UptimeDays = getVMUptime(domain)
		vm.GuestAgentOK = checkGuestAgent(domain)
		vm.NetworkIPs = getVMIPs(domain)
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
	// Conservative check: The guest agent cannot be reliably detected via
	// libvirt Go bindings without CGO constants that may not be available.
	//
	// A proper check would use:
	// - domain.QemuAgentCommand() to ping the agent
	// - domain.GetInterfaceAddresses() with DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT
	//
	// For now, we return false (conservative) to avoid false positives.
	// Users should verify guest agent manually with: virsh qemu-agent-command <vm> '{"execute":"guest-ping"}'
	return false
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
	// Try ARP cache first
	cmd := exec.Command("sh", "-c", fmt.Sprintf("arp -an | grep -i %s | awk '{print $2}' | tr -d '()'", mac))
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		ip := strings.TrimSpace(string(output))
		if ip != "" {
			return ip
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
