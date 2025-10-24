//go:build darwin
// +build darwin

// pkg/kvm/backup_stub_darwin.go
// macOS stub for VM backup operations

package kvm

import (
	"context"
	"errors"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// NewVMBackupOrchestrator stub
func NewVMBackupOrchestrator(rc *eos_io.RuntimeContext, opts OrchestratorOptions) (*VMBackupOrchestrator, error) {
	return nil, errors.New(errLibvirtMacOS)
}

// VMBackupOrchestrator.BackupAll stub
func (o *VMBackupOrchestrator) BackupAll() (*BatchBackupSummary, error) {
	return nil, errors.New(errLibvirtMacOS)
}

// BackupManager.Create stub
func (bm *BackupManager) Create(ctx context.Context, vmName, diskPath string) (string, error) {
	return "", errors.New(errLibvirtMacOS)
}

// BackupManager.CreateSnapshot stub
func (bm *BackupManager) CreateSnapshot(ctx context.Context, vmName string) (string, error) {
	return "", errors.New(errLibvirtMacOS)
}
