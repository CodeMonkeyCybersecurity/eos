//go:build darwin
// +build darwin

// pkg/kvm/guest_agent_stub_darwin.go
// macOS stub for QEMU guest agent operations

package kvm

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// EnableGuestExec stub
func EnableGuestExec(rc *eos_io.RuntimeContext, vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// EnableGuestExecBulk stub
func EnableGuestExecBulk(rc *eos_io.RuntimeContext, skipConfirm bool) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// AddGuestAgentToVMs stub
func AddGuestAgentToVMs(rc *eos_io.RuntimeContext, config *GuestAgentAddConfig) (*GuestAgentAddResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// AssessVMsForGuestAgent stub
func AssessVMsForGuestAgent(ctx context.Context, vmNames []string) (needsUpdate, hasAgent []string, err error) {
	return nil, nil, fmt.Errorf(errLibvirtMacOS)
}

// MakeBatches stub
func MakeBatches(items []string, batchSize int) [][]string {
	return nil
}
