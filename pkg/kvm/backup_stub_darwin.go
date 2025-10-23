//go:build darwin
// +build darwin

// pkg/kvm/backup_stub_darwin.go
// macOS stub for VM backup operations

package kvm

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// NewVMBackupOrchestrator stub
func NewVMBackupOrchestrator(rc *eos_io.RuntimeContext, opts OrchestratorOptions) (*VMBackupOrchestrator, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// VMBackupOrchestrator.BackupAll stub
func (o *VMBackupOrchestrator) BackupAll() (*BatchBackupSummary, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// BackupManager.Create stub
func (bm *BackupManager) Create(ctx context.Context, vmName, diskPath string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// BackupManager.CreateSnapshot stub
func (bm *BackupManager) CreateSnapshot(ctx context.Context, vmName string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}
