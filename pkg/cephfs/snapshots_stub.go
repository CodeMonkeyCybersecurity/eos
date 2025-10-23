//go:build darwin
// +build darwin

package cephfs

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CreateSnapshot stub for Mac
func (c *CephClient) CreateSnapshot(rc *eos_io.RuntimeContext, opts *SnapshotCreateOptions) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// ListSnapshots stub for Mac
func (c *CephClient) ListSnapshots(rc *eos_io.RuntimeContext, volumeName string, subVolume ...string) ([]*SnapshotInfo, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// DeleteSnapshot stub for Mac
func (c *CephClient) DeleteSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// RollbackSnapshot stub for Mac
func (c *CephClient) RollbackSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName string) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// RollbackToSnapshot stub for Mac (alias for RollbackSnapshot)
func (c *CephClient) RollbackToSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// ProtectSnapshot stub for Mac
func (c *CephClient) ProtectSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// UnprotectSnapshot stub for Mac
func (c *CephClient) UnprotectSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}
