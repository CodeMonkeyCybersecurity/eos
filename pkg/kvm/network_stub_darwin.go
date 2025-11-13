//go:build darwin
// +build darwin

// pkg/kvm/network_stub_darwin.go
// macOS stub for KVM network operations

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// ConfigureKVMBridge stub
func ConfigureKVMBridge(rc *eos_io.RuntimeContext) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// GetAllVMsWithNetworkInfo stub
func GetAllVMsWithNetworkInfo() ([]VMEntry, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}
