//go:build darwin
// +build darwin

// pkg/kvm/output_stub_darwin.go
// macOS stub for KVM output/display operations

package kvm

import "fmt"

// OutputVMs stub
func OutputVMs(vms []VMInfo, config *OutputConfig) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// OutputTable stub
func OutputTable(vms []VMInfo, showDrift, showUsage, detailed bool) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// OutputJSON stub
func OutputJSON(vms []VMInfo) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// OutputYAML stub
func OutputYAML(vms []VMInfo) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// PrintUpgradeResults stub
func PrintUpgradeResults(results []*UpgradeAndRebootResult) {
	// No-op on macOS
}
