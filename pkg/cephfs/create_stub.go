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

// ValidateConfig validates the provided configuration (stub for macOS)
func ValidateConfig(config *Config) error {
	if config.Name == "" {
		return fmt.Errorf("volume name is required")
	}
	if config.ReplicationSize < 0 || config.ReplicationSize > 10 {
		return fmt.Errorf("replication size must be between 1 and 10")
	}
	if config.PGNum < 0 || config.PGNum > 32768 {
		return fmt.Errorf("PG number must be between 1 and 32768")
	}
	return nil
}

// BuildMountArgs builds mount command arguments from config (stub for macOS)
func BuildMountArgs(config *Config) []string {
	// Return empty slice on macOS since CephFS mounting is not supported
	return []string{}
}

// ShouldPersistMount checks if mount should be persisted to fstab (stub for macOS)
func ShouldPersistMount(config *Config) bool {
	// Always return false on macOS since CephFS mounting is not supported
	return false
}
