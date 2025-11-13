//go:build darwin
// +build darwin

// pkg/kvm/orchestration_stub_darwin.go
// macOS stub for Nomad orchestration and VM pool management

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// NewNomadOrchestrator stub
func NewNomadOrchestrator(rc *eos_io.RuntimeContext, nomadAddr string) (*NomadOrchestrator, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// NomadOrchestrator.CreateVMJob stub
func (no *NomadOrchestrator) CreateVMJob(vmJob *NomadVMJob) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// NomadOrchestrator.DeleteVMJob stub
func (no *NomadOrchestrator) DeleteVMJob(jobID string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// NomadOrchestrator.GetJobStatus stub
func (no *NomadOrchestrator) GetJobStatus(jobID string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// NomadOrchestrator.ListVMJobs stub
func (no *NomadOrchestrator) ListVMJobs() ([]*NomadVMJob, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// NomadOrchestrator.ScaleVMPool stub
func (no *NomadOrchestrator) ScaleVMPool(poolName string, targetCount int) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// NomadOrchestrator.CreateVMPoolJob stub
func (no *NomadOrchestrator) CreateVMPoolJob(pool *VMPool) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// NomadOrchestrator.GetAllocationStatus stub
func (no *NomadOrchestrator) GetAllocationStatus(jobID string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// NewVMPoolManager stub
func NewVMPoolManager(rc *eos_io.RuntimeContext, consulAddr, nomadAddr string) (*VMPoolManager, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// VMPoolManager.CreatePool stub
func (pm *VMPoolManager) CreatePool(pool *VMPool) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// VMPoolManager.ScalePool stub
func (pm *VMPoolManager) ScalePool(poolName string, targetSize int) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// VMPoolManager.DeletePool stub
func (pm *VMPoolManager) DeletePool(poolName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// VMPoolManager.ListPools stub
func (pm *VMPoolManager) ListPools() []*VMPool {
	return nil
}

// VMPoolManager.GetPool stub
func (pm *VMPoolManager) GetPool(poolName string) (*VMPool, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// VMPoolManager.Stop stub
func (pm *VMPoolManager) Stop() {
	// No-op on macOS
}

// NewOrchestratedVMManager stub
func NewOrchestratedVMManager(rc *eos_io.RuntimeContext, consulAddr, nomadAddr string) (*OrchestratedVMManager, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// OrchestratedVMManager.CreateOrchestratedVM stub
func (om *OrchestratedVMManager) CreateOrchestratedVM(vmName string, enableNomad bool) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// OrchestratedVMManager.DestroyOrchestratedVM stub
func (om *OrchestratedVMManager) DestroyOrchestratedVM(vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// OrchestratedVMManager.ListOrchestratedVMs stub
func (om *OrchestratedVMManager) ListOrchestratedVMs() ([]*OrchestratedVM, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// OrchestratedVMManager.GetVMStatus stub
func (om *OrchestratedVMManager) GetVMStatus(vmName string) (*OrchestratedVM, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}
