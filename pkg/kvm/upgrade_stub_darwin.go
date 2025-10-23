//go:build darwin
// +build darwin

// pkg/kvm/upgrade_stub_darwin.go
// macOS stub for KVM upgrade operations

package kvm

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// DefaultPackageUpgradeConfig stub
func DefaultPackageUpgradeConfig() *PackageUpgradeConfig {
	return &PackageUpgradeConfig{}
}

// UpgradeVMPackages stub
func UpgradeVMPackages(rc *eos_io.RuntimeContext, vmName string, cfg *PackageUpgradeConfig) (*PackageUpgradeResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// DefaultUpgradeAndRebootConfig stub
func DefaultUpgradeAndRebootConfig() *UpgradeAndRebootConfig {
	return &UpgradeAndRebootConfig{}
}

// UpgradeAndRebootVM stub
func UpgradeAndRebootVM(rc *eos_io.RuntimeContext, vmName string, cfg *UpgradeAndRebootConfig) (*UpgradeAndRebootResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// UpgradeAndRebootMultiple stub
func UpgradeAndRebootMultiple(rc *eos_io.RuntimeContext, vmNames []string, cfg *UpgradeAndRebootConfig, rolling bool, batchSize int, waitBetween time.Duration) ([]*UpgradeAndRebootResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// UpgradeAndRebootVMsWithDrift stub
func UpgradeAndRebootVMsWithDrift(rc *eos_io.RuntimeContext, cfg *UpgradeAndRebootConfig, rolling bool, batchSize int, waitBetween time.Duration) ([]*UpgradeAndRebootResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}
