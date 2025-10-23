//go:build darwin
// +build darwin

package cephfs

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CreateVolume stub for macOS (package-level function)
func CreateVolume(rc *eos_io.RuntimeContext, config *Config) error {
	return fmt.Errorf("CephFS volume creation not available on macOS - deploy to Ubuntu Linux to use this feature")
}

// CreateMountPoint stub for macOS
func CreateMountPoint(rc *eos_io.RuntimeContext, config *Config) error {
	return fmt.Errorf("CephFS mount point creation not available on macOS - deploy to Ubuntu Linux to use this feature")
}
