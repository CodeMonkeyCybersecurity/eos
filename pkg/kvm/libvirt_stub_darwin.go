//go:build darwin
// +build darwin

// pkg/kvm/libvirt_stub_darwin.go
// macOS stub for libvirt operations - not available on macOS

package kvm

import (
	"context"
	"fmt"
)

const errLibvirtMacOS = "libvirt operations not available on macOS - deploy to Linux to use KVM features"

// SetLibvirtDefaultNetworkAutostart stub
func SetLibvirtDefaultNetworkAutostart() error {
	return fmt.Errorf(errLibvirtMacOS)
}

// DestroyDomain stub
func DestroyDomain(ctx context.Context, vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// UndefineDomain stub
func UndefineDomain(ctx context.Context, vmName string, removeStorage bool) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// GetDomainState stub
func GetDomainState(ctx context.Context, vmName string) (string, error) {
	return "", fmt.Errorf(errLibvirtMacOS)
}

// StartDomain stub
func StartDomain(ctx context.Context, vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// ShutdownDomain stub
func ShutdownDomain(ctx context.Context, vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// SetDomainAutostart stub
func SetDomainAutostart(ctx context.Context, vmName string, autostart bool) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// ListAllDomains stub
func ListAllDomains(ctx context.Context) ([]string, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// GetDomainInfo stub
func GetDomainInfo(ctx context.Context, vmName string) (map[string]interface{}, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}
