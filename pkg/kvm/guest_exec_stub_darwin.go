//go:build darwin
// +build darwin

// pkg/kvm/guest_exec_stub_darwin.go
// macOS stub for guest execution operations

package kvm

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// DefaultGuestExecConfig stub
func DefaultGuestExecConfig() *GuestExecConfig {
	return &GuestExecConfig{}
}

// GuestExecCommand stub
func GuestExecCommand(rc *eos_io.RuntimeContext, vmName string, cfg *GuestExecConfig) (*GuestExecResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// GuestExecScript stub
func GuestExecScript(rc *eos_io.RuntimeContext, vmName string, script string, timeout time.Duration) (*GuestExecResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// RunAddGuestAgentOperation stub
func RunAddGuestAgentOperation(rc *eos_io.RuntimeContext, config *AddOperationConfig) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// RunEnableGuestExecOperation stub
func RunEnableGuestExecOperation(rc *eos_io.RuntimeContext, config *EnableOperationConfig) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// RunRestartVMsOperation stub
func RunRestartVMsOperation(rc *eos_io.RuntimeContext, config *RestartOperationConfig) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// RunRescueModeOperation stub
func RunRescueModeOperation(rc *eos_io.RuntimeContext, vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}
