//go:build darwin
// +build darwin

// pkg/kvm/consul_stub_darwin.go
// macOS stub for Consul integration

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// RegisterVMWithConsul stub
func RegisterVMWithConsul(rc *eos_io.RuntimeContext, vmName, ipAddress string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// EnableConsulAutoRegistrationForVM stub
func EnableConsulAutoRegistrationForVM(rc *eos_io.RuntimeContext, vmName string, env *environment.DeploymentEnvironment) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// GenerateConsulCloudInit stub
func GenerateConsulCloudInit(rc *eos_io.RuntimeContext, config ConsulAutoRegisterConfig) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// WriteConsulCloudInitISO stub
func WriteConsulCloudInitISO(rc *eos_io.RuntimeContext, vmName string, cloudInit string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// NewConsulOrchestrator stub
func NewConsulOrchestrator(rc *eos_io.RuntimeContext, consulAddr string) (*ConsulOrchestrator, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// ConsulOrchestrator.SetIPRange stub
func (co *ConsulOrchestrator) SetIPRange(ipRange *IPRange) {
	// No-op on macOS
}

// ConsulOrchestrator.RegisterVM stub
func (co *ConsulOrchestrator) RegisterVM(vm *VMRegistration) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// ConsulOrchestrator.DeregisterVM stub
func (co *ConsulOrchestrator) DeregisterVM(vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// ConsulOrchestrator.AllocateIP stub
func (co *ConsulOrchestrator) AllocateIP(vmName string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// ConsulOrchestrator.ReleaseIP stub
func (co *ConsulOrchestrator) ReleaseIP(vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// ConsulOrchestrator.GetVMHealth stub
func (co *ConsulOrchestrator) GetVMHealth(vmName string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// ConsulOrchestrator.ListVMs stub
func (co *ConsulOrchestrator) ListVMs() ([]*OrchestratedVM, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}
