// pkg/kvm/types.go
// Common types used across KVM package (no build tags)

package kvm

import (
	"path/filepath"
	"time"
)

// Configuration variables for KVM tenant VMs
var (
	// UserProvidedVMName allows custom VM naming (flag-based)
	UserProvidedVMName string

	// VmPrefix is the default prefix for auto-generated VM names
	VmPrefix = "tenant-"

	// TenantDistro specifies which distribution to use for tenant VMs
	TenantDistro = "centos-stream9"

	// ImageDir is where VM disk images are stored
	ImageDir = "/var/lib/libvirt/images"

	// VmBaseIDFile tracks the next available VM ID for auto-naming
	VmBaseIDFile = filepath.Join(ImageDir, ".vm_id_counter")

	// SshKeyOverride allows specifying a custom SSH key path
	SshKeyOverride string

	// IsoPathOverride allows specifying a custom ISO path
	IsoPathOverride string

	// IsoDefaultPath is the default ISO location for CentOS Stream 9
	IsoDefaultPath = "/srv/iso/CentOS-Stream-9-latest-x86_64-boot.iso"
)

// CloudInitConfig represents cloud-init configuration
type CloudInitConfig struct {
	VMName        string
	Hostname      string
	PublicKey     string
	SSHPublicKey  string
	UserData      string
	MetaData      string
	NetworkConfig string
	CloudImg      string
	DiskSizeGB    int
	UseUEFI       bool
}

// VMEntry represents a VM entry for network management
type VMEntry struct {
	Name       string
	DomainName string
	State      string
	Network    string
	MACAddress string
	Protocol   string
	IPAddress  string
	IP         string // Alias for IPAddress
	MAC        string // Alias for MACAddress
}

// VMInfo contains comprehensive information about a VM
type VMInfo struct {
	Name            string
	UUID            string
	State           string
	VCPUs           int
	MemoryMB        int
	QEMUVersion     string
	HostQEMUVersion string
	DriftDetected   bool
	UptimeDays      int
	GuestAgentOK    bool
	NetworkIPs      []string
	DiskPaths       []string
}

// RestartConfig contains configuration for VM restart operations
type RestartConfig struct {
	CreateSnapshot   bool
	SnapshotName     string
	ShutdownTimeout  time.Duration
	SkipSafetyChecks bool
	WaitForBoot      bool
	BootTimeout      time.Duration
}

// DefaultRestartConfig returns a safe default configuration
func DefaultRestartConfig() *RestartConfig {
	return &RestartConfig{
		CreateSnapshot:   false, // Opt-in for safety
		SnapshotName:     "",    // Will be set automatically if needed
		ShutdownTimeout:  5 * time.Minute,
		SkipSafetyChecks: false,
		WaitForBoot:      true,
		BootTimeout:      5 * time.Minute,
	}
}

// FilterVMsByState filters VMs by their state
func FilterVMsByState(vms []VMInfo, state string) []VMInfo {
	if state == "" {
		return vms
	}

	filtered := make([]VMInfo, 0)
	for _, vm := range vms {
		if vm.State == state {
			filtered = append(filtered, vm)
		}
	}
	return filtered
}
