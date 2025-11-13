//go:build darwin
// +build darwin

// pkg/kvm/utils_stub_darwin.go
// macOS stub for KVM utility functions

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// SetLibvirtACL stub
func SetLibvirtACL(rc *eos_io.RuntimeContext, dir string) {
	// No-op on macOS
}

// ParseMemorySize stub
func ParseMemorySize(size string) (int, error) {
	return 0, fmt.Errorf(errLibvirtMacOS)
}

// ParseDiskSize stub
func ParseDiskSize(size string) (int, error) {
	return 0, fmt.Errorf(errLibvirtMacOS)
}

// GenerateVMName stub
func GenerateVMName(prefix string) string {
	return prefix + "-stub"
}

// TemplateContext.Validate stub
func (c *TemplateContext) Validate() error {
	return fmt.Errorf(errLibvirtMacOS)
}

// PromptConfirmation stub
func PromptConfirmation(rc *eos_io.RuntimeContext, message string) bool {
	return false
}

// ShowImpactSummary stub
func ShowImpactSummary(rc *eos_io.RuntimeContext, vmsNeedingUpdate []string, batchSize, waitBetween int) {
	// No-op on macOS
}
