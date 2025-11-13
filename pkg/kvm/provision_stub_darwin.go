//go:build darwin
// +build darwin

// pkg/kvm/provision_stub_darwin.go
// macOS stub for VM provisioning operations

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

// ProvisionCloudInitVM stub
func ProvisionCloudInitVM(log *zap.Logger, cfg CloudInitConfig) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// ProvisionKickstartTenantVM stub
func ProvisionKickstartTenantVM(rc *eos_io.RuntimeContext, vmName, pubKeyPath string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// GenerateSecureCloudInit stub
func GenerateSecureCloudInit(config *SecureVMConfig) string {
	return ""
}
