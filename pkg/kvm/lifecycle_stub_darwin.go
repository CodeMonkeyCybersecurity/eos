//go:build darwin
// +build darwin

// pkg/kvm/lifecycle_stub_darwin.go
// macOS stub for KVM lifecycle operations

package kvm

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

// InstallKVM stub
func InstallKVM(rc *eos_io.RuntimeContext) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// EnsureLibvirtd stub
func EnsureLibvirtd(rc *eos_io.RuntimeContext) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// ListVMs stub
func ListVMs(rc *eos_io.RuntimeContext) ([]VMInfo, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// GetVMByName stub
func GetVMByName(ctx context.Context, name string) (*VMInfo, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// FilterVMsWithDrift stub
func FilterVMsWithDrift(vms []VMInfo) []VMInfo {
	return nil
}

// PrintAllVMsTable stub
func PrintAllVMsTable() error {
	return fmt.Errorf(errLibvirtMacOS)
}

// StartInstallStatusTicker stub
func StartInstallStatusTicker(ctx context.Context, log *zap.Logger, vmName, diskPath string) {
	// No-op on macOS
}

// IsVMRunning stub
func IsVMRunning(ctx context.Context, vmName string) bool {
	return false
}

// ListAllVMNames stub
func ListAllVMNames(ctx context.Context) ([]string, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// FilterVMsByState stub
func FilterVMsByState(vms []VMInfo, state string) []VMInfo {
	return nil
}

// FilterVMsForBackup stub
func FilterVMsForBackup(vms []VMInfo, filter BackupFilter) []VMInfo {
	return nil
}

// VMInfo.CanBackup stub
func (vm *VMInfo) CanBackup(allowCrashConsistent bool) (bool, string) {
	return false, errLibvirtMacOS
}

// VMInfo.FormatSize stub
func (vm *VMInfo) FormatSize() string {
	return "0 GB"
}
