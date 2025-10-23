//go:build darwin
// +build darwin

// pkg/kvm/transfer_stub_darwin.go
// macOS stub for VM file transfer operations

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// SyncFileBetweenVMs stub
func SyncFileBetweenVMs(rc *eos_io.RuntimeContext, sourceVM, guestPath, destVM, destGuestPath string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// CopyOutFromVM stub
func CopyOutFromVM(rc *eos_io.RuntimeContext, vmName, guestPath, hostFile string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// CopyInToVM stub
func CopyInToVM(rc *eos_io.RuntimeContext, vmName, hostPath, guestDir string) error {
	return fmt.Errorf(errLibvirtMacOS)
}
