//go:build darwin
// +build darwin

// pkg/kvm/simple_vm_stub_darwin.go
// macOS stub for simple VM creation

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CreateSimpleUbuntuVM stub
func CreateSimpleUbuntuVM(rc *eos_io.RuntimeContext, vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}
