//go:build darwin
// +build darwin

package cephfs

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// DeployTerraform stub for macOS
func DeployTerraform(rc *eos_io.RuntimeContext, config *Config) error {
	return fmt.Errorf("Ceph Terraform deployment not available on macOS - deploy to Ubuntu Linux to use this feature")
}
