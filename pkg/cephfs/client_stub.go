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
