//go:build linux

// pkg/kvm/libvirt.go
// Libvirt Go bindings helper functions to replace virsh commands

package kvm

import (
	"context"
	"fmt"

	"libvirt.org/go/libvirt"
)

func SetLibvirtDefaultNetworkAutostart() error {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	network, err := conn.LookupNetworkByName("default")
	if err != nil {
		return fmt.Errorf("failed to lookup default network: %w", err)
	}
	defer func() { _ = network.Free() }()

	// Start network if not already active
	isActive, err := network.IsActive()
	if err != nil {
		return fmt.Errorf("failed to check network status: %w", err)
	}

	if !isActive {
		if err := network.Create(); err != nil {
			return fmt.Errorf("failed to start network: %w", err)
		}
	}

	// Set autostart
	if err := network.SetAutostart(true); err != nil {
		return fmt.Errorf("failed to set network autostart: %w", err)
	}

	return nil
}

// DestroyDomain stops a running VM
func DestroyDomain(ctx context.Context, vmName string) error {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		// Domain doesn't exist, that's fine
		return nil
	}
	defer domain.Free()

	// Check if running
	state, _, err := domain.GetState()
	if err != nil {
		return fmt.Errorf("failed to get domain state: %w", err)
	}

	if state == libvirt.DOMAIN_RUNNING {
		if err := domain.Destroy(); err != nil {
			return fmt.Errorf("failed to destroy domain: %w", err)
		}
	}

	return nil
}

// UndefineDomain removes a VM definition
func UndefineDomain(ctx context.Context, vmName string, removeStorage bool) error {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		// Domain doesn't exist, that's fine
		return nil
	}
	defer domain.Free()

	// Use simple Undefine instead of UndefineFlags to avoid CGO constant issues
	// UndefineFlags with specific flags would be better but requires CGO constants
	if err := domain.Undefine(); err != nil {
		return fmt.Errorf("failed to undefine domain: %w", err)
	}

	// Note: This doesn't automatically remove NVRAM or managed save files
	// For full cleanup, users may need to manually remove:
	// - /var/lib/libvirt/qemu/nvram/<vm>_VARS.fd
	// - /var/lib/libvirt/qemu/save/<vm>.save

	return nil
}

// GetDomainState returns the state of a VM
func GetDomainState(ctx context.Context, vmName string) (string, error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return "", fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return "", fmt.Errorf("domain not found: %w", err)
	}
	defer domain.Free()

	state, _, err := domain.GetState()
	if err != nil {
		return "", fmt.Errorf("failed to get state: %w", err)
	}

	return stateToString(state), nil
}

// StartDomain starts a VM
func StartDomain(ctx context.Context, vmName string) error {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("domain not found: %w", err)
	}
	defer domain.Free()

	// Check if already running
	state, _, err := domain.GetState()
	if err != nil {
		return fmt.Errorf("failed to get state: %w", err)
	}

	if state == libvirt.DOMAIN_RUNNING {
		return nil // Already running
	}

	if err := domain.Create(); err != nil {
		return fmt.Errorf("failed to start domain: %w", err)
	}

	return nil
}

// ShutdownDomain sends ACPI shutdown to a VM
func ShutdownDomain(ctx context.Context, vmName string) error {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("domain not found: %w", err)
	}
	defer domain.Free()

	// Use explicit type cast for libvirt constant (required for Go bindings)
	if err := domain.ShutdownFlags(libvirt.DomainShutdownFlags(libvirt.DOMAIN_SHUTDOWN_ACPI_POWER_BTN)); err != nil {
		return fmt.Errorf("failed to shutdown domain: %w", err)
	}

	return nil
}

// SetDomainAutostart sets the autostart flag for a VM
func SetDomainAutostart(ctx context.Context, vmName string, autostart bool) error {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("domain not found: %w", err)
	}
	defer domain.Free()

	if err := domain.SetAutostart(autostart); err != nil {
		return fmt.Errorf("failed to set autostart: %w", err)
	}

	return nil
}

// ListAllDomains returns all domain names
func ListAllDomains(ctx context.Context) ([]string, error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domains, err := conn.ListAllDomains(0)
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	var names []string
	for _, domain := range domains {
		name, err := domain.GetName()
		if err == nil {
			names = append(names, name)
		}
		domain.Free()
	}

	return names, nil
}

// GetDomainInfo returns basic info about a domain
func GetDomainInfo(ctx context.Context, vmName string) (map[string]interface{}, error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return nil, fmt.Errorf("domain not found: %w", err)
	}
	defer domain.Free()

	info, err := domain.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get info: %w", err)
	}

	state, _, _ := domain.GetState()
	uuid, _ := domain.GetUUIDString()

	return map[string]interface{}{
		"state":       stateToString(state),
		"max_mem":     info.MaxMem,
		"memory":      info.Memory,
		"nr_virt_cpu": info.NrVirtCpu,
		"cpu_time":    info.CpuTime,
		"uuid":        uuid,
	}, nil
}
