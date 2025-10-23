//go:build darwin
// +build darwin

package cephfs

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CephClient stub for Mac - provides interface compatibility
type CephClient struct{}

// ClientConfig stub for Mac
type ClientConfig struct {
	ClusterName   string
	User          string
	ConfigFile    string
	MonHosts      []string
	UseVault      bool
	KeyringPath   string
	ConsulEnabled bool
	ConsulService string
}

// NewCephClient stub - returns error on Mac
func NewCephClient(rc *eos_io.RuntimeContext, config *ClientConfig) (*CephClient, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS - this is development only. Deploy to Linux to use SDK features")
}

// Connect stub
func (c *CephClient) Connect() error {
	return fmt.Errorf("Ceph SDK not available on macOS")
}

// Disconnect stub
func (c *CephClient) Disconnect() error {
	return nil
}

// GetClusterStats stub
func (c *CephClient) GetClusterStats() (map[string]interface{}, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS")
}

// Close stub
func (c *CephClient) Close() error {
	return nil
}

// UpdatePool stub
func (c *CephClient) UpdatePool(rc *eos_io.RuntimeContext, poolName string, opts *PoolUpdateOptions) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// VolumeExists stub
func (c *CephClient) VolumeExists(rc *eos_io.RuntimeContext, name string) (bool, error) {
	return false, fmt.Errorf("Ceph SDK not available on macOS")
}

// ListVolumes stub
func (c *CephClient) ListVolumes(rc *eos_io.RuntimeContext) ([]*VolumeInfo, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// GetVolumeInfo stub
func (c *CephClient) GetVolumeInfo(rc *eos_io.RuntimeContext, volumeName string) (*VolumeInfo, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// CreateVolume stub
func (c *CephClient) CreateVolume(rc *eos_io.RuntimeContext, opts *VolumeCreateOptions) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// DeleteVolume stub
func (c *CephClient) DeleteVolume(rc *eos_io.RuntimeContext, volumeName string, skipSnapshot bool) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// UpdateVolume stub
func (c *CephClient) UpdateVolume(rc *eos_io.RuntimeContext, volumeName string, opts *VolumeUpdateOptions) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// ListPools stub - defined in pools_stub.go already but referenced here for clarity
// GetPoolInfo stub - defined in pools_stub.go already
// CreatePool stub - defined in pools_stub.go already
// DeletePool stub - defined in pools_stub.go already
