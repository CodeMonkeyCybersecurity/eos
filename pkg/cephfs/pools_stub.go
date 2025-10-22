//go:build darwin
// +build darwin

package cephfs

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CreatePool stub for Mac
func (c *CephClient) CreatePool(rc *eos_io.RuntimeContext, opts *PoolCreateOptions) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// ListPools stub for Mac
func (c *CephClient) ListPools(rc *eos_io.RuntimeContext) ([]PoolInfo, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// GetPool stub for Mac
func (c *CephClient) GetPool(rc *eos_io.RuntimeContext, name string) (*PoolInfo, error) {
	return nil, fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// DeletePool stub for Mac
func (c *CephClient) DeletePool(rc *eos_io.RuntimeContext, poolName string, skipSnapshot bool) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}

// SetPoolQuota stub for Mac
func (c *CephClient) SetPoolQuota(rc *eos_io.RuntimeContext, poolName string, maxBytes, maxObjects uint64) error {
	return fmt.Errorf("Ceph SDK not available on macOS - deploy to Linux to use this feature")
}
