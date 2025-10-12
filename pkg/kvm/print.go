//go:build linux

// pkg/kvm/print.go

package kvm

import (
	"fmt"
	"strings"
)

// PrintAllVMsTable retrieves all VMs with network info and prints a table.
func PrintAllVMsTable() error {
	vms, err := GetAllVMsWithNetworkInfo()
	if err != nil {
		return err
	}

	// Header
	fmt.Printf("%-20s %-12s %-12s %-20s %-8s %-15s\n",
		"VM NAME", "STATE", "NETWORK", "MAC", "PROTO", "IP")
	fmt.Printf("%-20s %-12s %-12s %-20s %-8s %-15s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 12),
		strings.Repeat("-", 12),
		strings.Repeat("-", 20),
		strings.Repeat("-", 8),
		strings.Repeat("-", 15),
	)

	// Rows
	for _, vm := range vms {
		fmt.Printf("%-20s %-12s %-12s %-20s %-8s %-15s\n",
			vm.Name, vm.State, vm.Network, vm.MACAddress, vm.Protocol, vm.IPAddress)
	}

	return nil
}
