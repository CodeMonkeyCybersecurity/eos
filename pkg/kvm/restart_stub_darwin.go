//go:build darwin
// +build darwin

// pkg/kvm/restart_stub_darwin.go
// macOS stub for KVM restart operations

package kvm

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// DefaultRestartConfig stub
func DefaultRestartConfig() *RestartConfig {
	return &RestartConfig{}
}

// RestartVM stub
func RestartVM(ctx context.Context, vmName string, cfg *RestartConfig) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// RestartMultipleVMs stub
func RestartMultipleVMs(ctx context.Context, vmNames []string, cfg *RestartConfig, rolling bool, batchSize int, waitBetween time.Duration) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// RestartVMsWithDrift stub
func RestartVMsWithDrift(ctx context.Context, cfg *RestartConfig, rolling bool, batchSize int, waitBetween time.Duration) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// PromptVMRestart stub
func PromptVMRestart(rc *eos_io.RuntimeContext, vmName string) bool {
	return false
}
