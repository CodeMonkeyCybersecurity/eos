// pkg/kvm/types.go
// Common types used across KVM package (no build tags)

package kvm

import "time"

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
