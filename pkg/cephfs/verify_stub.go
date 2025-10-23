//go:build darwin
// +build darwin

package cephfs

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// VerifyCluster stub for macOS
func VerifyCluster(rc *eos_io.RuntimeContext, config *Config) error {
	return fmt.Errorf("Ceph cluster verification not available on macOS - deploy to Ubuntu Linux to use this feature")
}
