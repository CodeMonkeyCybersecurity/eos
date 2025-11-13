//go:build darwin
// +build darwin

// pkg/kvm/secure_vm_stub_darwin.go
// macOS stub for secure VM management

package kvm

import (
	"context"
	"fmt"
)

// DefaultSecureVMConfig stub
func DefaultSecureVMConfig(name string) *SecureVMConfig {
	return &SecureVMConfig{}
}

// FindDefaultSSHKeys stub
func FindDefaultSSHKeys() ([]string, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// CreateSecureVM stub
func CreateSecureVM(ctx context.Context, manager *KVMManager, config *SecureVMConfig) (*VMInfo, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// ValidateSecureVMConfig stub
func ValidateSecureVMConfig(config *SecureVMConfig) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// GetSecurityRecommendations stub
func GetSecurityRecommendations(config *SecureVMConfig) []string {
	return nil
}

// SecureVMConfig.ApplySecurityLevel stub
func (c *SecureVMConfig) ApplySecurityLevel(level string) {
	// No-op on macOS
}
