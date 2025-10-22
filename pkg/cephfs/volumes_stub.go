//go:build darwin
// +build darwin

package cephfs

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CreateVolume stub for Mac
func (c *CephClient) CreateVolume(rc *eos_io.RuntimeContext, opts *VolumeCreateOptions) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// ListVolumes stub for Mac
func (c *CephClient) ListVolumes(rc *eos_io.RuntimeContext) ([]VolumeInfo, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// GetVolume stub for Mac
func (c *CephClient) GetVolume(rc *eos_io.RuntimeContext, name string) (*VolumeInfo, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// DeleteVolume stub for Mac
func (c *CephClient) DeleteVolume(rc *eos_io.RuntimeContext, volumeName string, skipSnapshot bool) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// UpdateVolume stub for Mac
func (c *CephClient) UpdateVolume(rc *eos_io.RuntimeContext, volumeName string, opts *VolumeUpdateOptions) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}
