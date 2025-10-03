// +build !libvirt

// pkg/kvm/libvirt_stub.go
// Stub implementations when libvirt is not available

package kvm

import (
	"context"
	"fmt"
	"time"
)

const libvirtAvailable = false

var errLibvirtNotAvailable = fmt.Errorf("EOS was built without libvirt support. To enable KVM features:\n" +
	"  1. Install libvirt development libraries:\n" +
	"     - Ubuntu/Debian: sudo apt-get install libvirt-dev libvirt-daemon-system pkg-config\n" +
	"     - RHEL/CentOS: sudo yum install libvirt-devel libvirt-daemon-kvm pkg-config\n" +
	"  2. Rebuild EOS with: CGO_ENABLED=1 go build -tags libvirt .\n" +
	"  3. Or use install.sh which auto-detects and configures libvirt")

// Stub implementations that return helpful errors

func DestroyDomain(ctx context.Context, vmName string) error {
	return errLibvirtNotAvailable
}

func UndefineDomain(ctx context.Context, vmName string, removeStorage bool) error {
	return errLibvirtNotAvailable
}

func GetDomainState(ctx context.Context, vmName string) (string, error) {
	return "", errLibvirtNotAvailable
}

func StartDomain(ctx context.Context, vmName string) error {
	return errLibvirtNotAvailable
}

func ShutdownDomain(ctx context.Context, vmName string) error {
	return errLibvirtNotAvailable
}

func ListAllDomains(ctx context.Context) ([]string, error) {
	return nil, errLibvirtNotAvailable
}

func GetDomainInfo(ctx context.Context, vmName string) (map[string]interface{}, error) {
	return nil, errLibvirtNotAvailable
}

func SetLibvirtDefaultNetworkAutostart() error {
	return errLibvirtNotAvailable
}

func ListVMs(ctx context.Context) ([]VMInfo, error) {
	return nil, errLibvirtNotAvailable
}

func RestartVM(ctx context.Context, vmName string, cfg *RestartConfig) error {
	return errLibvirtNotAvailable
}

func RestartMultipleVMs(ctx context.Context, vmNames []string, cfg *RestartConfig, rolling bool, batchSize int, waitBetween time.Duration) error {
	return errLibvirtNotAvailable
}

func RestartVMsWithDrift(ctx context.Context, cfg *RestartConfig, rolling bool, batchSize int, waitBetween time.Duration) error {
	return errLibvirtNotAvailable
}
