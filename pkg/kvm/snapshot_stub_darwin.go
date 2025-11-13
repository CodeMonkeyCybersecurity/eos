//go:build darwin
// +build darwin

// pkg/kvm/snapshot_stub_darwin.go
// macOS stub for VM snapshot operations

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// NewSnapshotManager stub
func NewSnapshotManager(config *SnapshotConfig, logger otelzap.LoggerWithCtx) *SnapshotManager {
	return &SnapshotManager{}
}

// SnapshotManager.CreateSnapshot stub
func (sm *SnapshotManager) CreateSnapshot(rc *eos_io.RuntimeContext) (*SnapshotBackupResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// SnapshotManager.BackupSnapshot stub
func (sm *SnapshotManager) BackupSnapshot(rc *eos_io.RuntimeContext, snapshotName string) (*SnapshotBackupResult, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// SnapshotManager.RestoreSnapshot stub
func (sm *SnapshotManager) RestoreSnapshot(rc *eos_io.RuntimeContext, backupPath string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// SnapshotManager.VerifySnapshot stub
func (sm *SnapshotManager) VerifySnapshot(rc *eos_io.RuntimeContext, snapshotName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// SnapshotManager.ListSnapshots stub
func (sm *SnapshotManager) ListSnapshots(rc *eos_io.RuntimeContext) ([]*SnapshotInfo, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// SnapshotManager.DeleteSnapshot stub
func (sm *SnapshotManager) DeleteSnapshot(rc *eos_io.RuntimeContext, snapshotName string, deleteMetadata bool) error {
	return fmt.Errorf(errLibvirtMacOS)
}
