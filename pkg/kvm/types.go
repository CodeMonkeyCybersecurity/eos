//go:build linux

// pkg/kvm/types.go
// Common types used across KVM package (no build tags)

package kvm

import (
	"fmt"
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
	Name              string
	UUID              string
	State             string
	VCPUs             int
	MemoryMB          int
	QEMUVersion       string
	HostQEMUVersion   string
	DriftDetected     bool
	UptimeDays        int
	GuestAgentOK      bool
	GuestAgentStatus  string     // QEMU Guest Agent status: "INSTALLED", "NOT_INSTALLED", "DISABLED", "N/A"
	NetworkIPs        []string
	DiskPaths         []string
	Disks             []DiskInfo // Detailed disk information (added for backup support)
	MainDiskPath      string     // Path to vda (main disk for backup)
	DiskFormat        string     // Disk format: qcow2, raw, etc. (main disk)
	HasMultipleDisks  bool       // True if VM has more than one disk
	SupportsSnapshot  bool       // True if disk format supports snapshots (qcow2)
	OSInfo            string     // Operating system (e.g., "CentOS Stream 9", "Ubuntu 24.04")
	ConsulAgent       string     // Consul agent status: "YES", "NO", "DISABLED", "N/A"
	UpdatesNeeded     string     // OS updates status: "YES", "NO", "DISABLED", "N/A"
	DiskSizeGB        int        // Total allocated disk image size in GB
	DiskUsageGB       int        // Used disk space in GB (guest filesystem, requires guest agent)
	DiskTotalGB       int        // Total disk size from guest perspective in GB (requires guest agent)
	CPUUsagePercent   float64    // CPU usage percentage (requires running VM)
	MemoryUsageMB     int        // Memory usage in MB (requires running VM)
}

// DiskInfo represents detailed information about a single disk
type DiskInfo struct {
	Target          string // vda, sda, hdd, etc.
	Path            string // Full path to disk image
	Format          string // qcow2, raw, etc.
	SizeGB          int64  // Disk size in GB
	IsCloudInitSeed bool   // True if this is sda/hdd cloud-init seed
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

// BackupFilter defines filtering criteria for VM backups
type BackupFilter struct {
	ExcludeVMs     []string
	IncludeVMs     []string // If specified, only include these VMs
	IncludeStopped bool
}

// FilterVMsForBackup filters VMs based on backup criteria
func FilterVMsForBackup(vms []VMInfo, filter BackupFilter) []VMInfo {
	filtered := make([]VMInfo, 0)

	for _, vm := range vms {
		// Check include list first (if specified, only include these)
		if len(filter.IncludeVMs) > 0 {
			found := false
			for _, include := range filter.IncludeVMs {
				if vm.Name == include {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Check exclude list
		excluded := false
		for _, exclude := range filter.ExcludeVMs {
			if vm.Name == exclude {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Check stopped VMs
		if !filter.IncludeStopped && vm.State != "running" {
			continue
		}

		filtered = append(filtered, vm)
	}

	return filtered
}

// CanBackup checks if this VM can be backed up
func (vm *VMInfo) CanBackup(allowCrashConsistent bool) (bool, string) {
	// Check if main disk exists
	if vm.MainDiskPath == "" {
		return false, "no main disk (vda) found"
	}

	// Check if disk format supports snapshots
	if !vm.SupportsSnapshot {
		return false, "disk format does not support snapshots (qcow2 required)"
	}

	// Check guest agent
	if !vm.GuestAgentOK && !allowCrashConsistent {
		return false, "guest agent not available (use --allow-crash-consistent to override)"
	}

	return true, ""
}

// FormatSize formats disk size to human-readable format
func (vm *VMInfo) FormatSize() string {
	gb := int64(vm.DiskSizeGB)
	if gb < 1 {
		return fmt.Sprintf("%d MB", vm.DiskSizeGB*1024)
	}
	return fmt.Sprintf("%d GB", gb)
}
