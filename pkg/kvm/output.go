//go:build linux

// pkg/kvm/output.go
// Output formatting functions for KVM VM listings

package kvm

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"gopkg.in/yaml.v3"
)

// OutputConfig configures output formatting options
type OutputConfig struct {
	Format    string // table, json, yaml
	ShowDrift bool
	ShowUsage bool
	Detailed  bool
}

// OutputVMs formats and displays VM information based on configuration
func OutputVMs(vms []VMInfo, config *OutputConfig) error {
	if len(vms) == 0 {
		fmt.Println("No VMs found")
		return nil
	}

	switch config.Format {
	case "json":
		return OutputJSON(vms)
	case "yaml":
		return OutputYAML(vms)
	default:
		return OutputTable(vms, config.ShowDrift, config.ShowUsage, config.Detailed)
	}
}

// OutputTable renders VMs as a formatted table
func OutputTable(vms []VMInfo, showDrift, showUsage, detailed bool) error {
	table := tablewriter.NewWriter(os.Stdout)

	if showUsage {
		renderUsageTable(table, vms)
	} else if showDrift {
		renderDriftTable(table, vms)
	} else {
		renderStandardTable(table, vms)
	}

	table.Render()
	printSummary(vms, showDrift)

	return nil
}

// renderUsageTable displays resource usage information
func renderUsageTable(table *tablewriter.Table, vms []VMInfo) {
	table.Header("NAME", "STATE", "LOAD", "MEM_USED", "MEM_TOTAL", "DISK_USED", "DISK_TOTAL", "IPS", "TAILSCALE_IP")

	for _, vm := range vms {
		loadAvg := "N/A"
		if vm.GuestAgentOK && vm.CPUUsagePercent > 0 {
			loadAvg = fmt.Sprintf("%.2f", vm.CPUUsagePercent)
		}

		memUsed := "N/A"
		if vm.State == "running" && vm.MemoryUsageMB > 0 {
			memUsed = fmt.Sprintf("%d MB", vm.MemoryUsageMB)
		}

		memTotal := fmt.Sprintf("%d MB", vm.MemoryMB)

		diskUsed := "N/A"
		if vm.GuestAgentOK && vm.DiskUsageGB > 0 {
			diskUsed = fmt.Sprintf("%d GB", vm.DiskUsageGB)
		}

		diskTotal := "N/A"
		if vm.DiskSizeGB > 0 {
			diskTotal = fmt.Sprintf("%d GB", vm.DiskSizeGB)
		}

		ips := formatIPs(vm.NetworkIPs)
		tailscaleIP := formatOptional(vm.TailscaleIP)

		_ = table.Append(
			vm.Name,
			vm.State,
			loadAvg,
			memUsed,
			memTotal,
			diskUsed,
			diskTotal,
			ips,
			tailscaleIP,
		)
	}
}

// renderDriftTable displays QEMU version drift information
func renderDriftTable(table *tablewriter.Table, vms []VMInfo) {
	table.Header("NAME", "STATE", "QEMU", "HOST_QEMU", "DRIFT", "UPTIME", "IPS", "TAILSCALE_IP")

	for _, vm := range vms {
		drift := "NO"
		if vm.DriftDetected {
			drift = "YES"
		}

		ips := formatIPs(vm.NetworkIPs)
		tailscaleIP := formatOptional(vm.TailscaleIP)
		qemuVer := formatOptional(vm.QEMUVersion)
		hostVer := formatOptional(vm.HostQEMUVersion)

		_ = table.Append(
			vm.Name,
			vm.State,
			qemuVer,
			hostVer,
			drift,
			fmt.Sprintf("%dd", vm.UptimeDays),
			ips,
			tailscaleIP,
		)
	}
}

// renderStandardTable displays standard VM information
func renderStandardTable(table *tablewriter.Table, vms []VMInfo) {
	table.Header("NAME", "STATE", "VCPUS", "OS", "MEM", "DISK", "QEMU_GA", "CONSUL", "UPDATES", "IPS", "TAILSCALE_IP")

	for _, vm := range vms {
		consul := "N/A"
		if vm.GuestAgentOK {
			consul = vm.ConsulAgent
		}

		updates := "N/A"
		if vm.GuestAgentOK {
			updates = vm.UpdatesNeeded
		}

		ips := formatIPs(vm.NetworkIPs)
		tailscaleIP := formatOptional(vm.TailscaleIP)
		osInfo := formatOptional(vm.OSInfo)

		// Format memory with usage
		memInfo := "N/A"
		if vm.State == "running" && vm.MemoryUsageMB > 0 && vm.MemoryMB > 0 {
			usagePercent := float64(vm.MemoryUsageMB) / float64(vm.MemoryMB) * 100
			memInfo = fmt.Sprintf("%d MB (%.0f%%)", vm.MemoryMB, usagePercent)
		} else if vm.MemoryMB > 0 {
			memInfo = fmt.Sprintf("%d MB", vm.MemoryMB)
		}

		// Format disk with usage percentage
		diskInfo := "N/A"
		if vm.DiskSizeGB > 0 {
			if vm.DiskUsageGB > 0 && vm.DiskTotalGB > 0 {
				usagePercent := float64(vm.DiskUsageGB) / float64(vm.DiskTotalGB) * 100
				diskInfo = fmt.Sprintf("%d GB (%.0f%%)", vm.DiskTotalGB, usagePercent)
			} else {
				diskInfo = fmt.Sprintf("%d GB", vm.DiskSizeGB)
			}
		}

		// Format VCPUs with usage
		vcpuInfo := fmt.Sprintf("%d", vm.VCPUs)
		if vm.State == "running" && vm.CPUUsagePercent > 0 {
			vcpuInfo = fmt.Sprintf("%d (%.0f%%)", vm.VCPUs, vm.CPUUsagePercent)
		}

		// Get QEMU Guest Agent status
		qemuGA := formatOptional(vm.GuestAgentStatus)

		_ = table.Append(
			vm.Name,
			vm.State,
			vcpuInfo,
			osInfo,
			memInfo,
			diskInfo,
			qemuGA,
			consul,
			updates,
			ips,
			tailscaleIP,
		)
	}
}

// printSummary displays summary information after the table
func printSummary(vms []VMInfo, showDrift bool) {
	driftCount := 0
	disabledGuestExecCount := 0
	disabledVMs := []string{}

	for _, vm := range vms {
		if vm.DriftDetected {
			driftCount++
		}
		if vm.ConsulAgent == "DISABLED" || vm.UpdatesNeeded == "DISABLED" {
			disabledGuestExecCount++
			disabledVMs = append(disabledVMs, vm.Name)
		}
	}

	fmt.Printf("\nTotal VMs: %d", len(vms))
	if showDrift && driftCount > 0 {
		fmt.Printf(" (⚠ %d with QEMU drift)", driftCount)
	}
	fmt.Println()

	// Show warning about disabled guest-exec
	if disabledGuestExecCount > 0 {
		fmt.Println()
		fmt.Printf("⚠ %d VM(s) have guest-exec DISABLED:\n", disabledGuestExecCount)
		for _, vmName := range disabledVMs {
			fmt.Printf("  - %s\n", vmName)
		}
		fmt.Println()
		fmt.Println("To enable monitoring for these VMs, run:")
		fmt.Println("  eos update kvm --enable --guest-exec --name <vm-name>")
		fmt.Println()
		fmt.Println("Or to fix all at once:")
		fmt.Println("  eos update kvm --enable --guest-exec --all-disabled")
	}
}

// OutputJSON renders VMs as JSON
func OutputJSON(vms []VMInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(vms)
}

// OutputYAML renders VMs as YAML
func OutputYAML(vms []VMInfo) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer func() { _ = encoder.Close() }()
	return encoder.Encode(vms)
}

// formatIPs formats IP address list for display
func formatIPs(ips []string) string {
	if len(ips) == 0 {
		return "N/A"
	}
	if len(ips) == 1 {
		return ips[0]
	}
	return fmt.Sprintf("%s (+%d)", ips[0], len(ips)-1)
}

// formatOptional formats optional string fields
func formatOptional(value string) string {
	if value == "" {
		return "N/A"
	}
	return value
}

// PrintUpgradeResults displays a summary of upgrade operations
func PrintUpgradeResults(results []*UpgradeAndRebootResult) {
	if len(results) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("UPGRADE SUMMARY: %d VM(s) processed\n", len(results))
	fmt.Println("═══════════════════════════════════════")

	successCount := 0
	failedCount := 0
	driftResolvedCount := 0

	for _, r := range results {
		if r.Success {
			successCount++
			if r.DriftResolved {
				driftResolvedCount++
			}
		} else {
			failedCount++
		}

		status := "✓"
		if !r.Success {
			status = "✗"
		}

		fmt.Printf("%s %s\n", status, r.VMName)
		if r.PackageResult != nil {
			fmt.Printf("  Packages upgraded: %d\n", r.PackageResult.PackagesUpgraded)
		}
		if r.RestartedVM {
			fmt.Printf("  Restarted: yes\n")
		}
		if r.DriftResolved {
			fmt.Printf("  QEMU drift: resolved\n")
		} else if r.RestartedVM {
			fmt.Printf("  QEMU drift: still present (check manually)\n")
		}
		if r.SnapshotCreated {
			fmt.Printf("  Snapshot: %s\n", r.SnapshotName)
		}
		if r.ErrorMessage != "" {
			fmt.Printf("  Error: %s\n", r.ErrorMessage)
		}
		fmt.Printf("  Duration: %s\n", r.Duration)
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("Success: %d  Failed: %d  Drift Resolved: %d\n",
		successCount, failedCount, driftResolvedCount)
	fmt.Println("═══════════════════════════════════════")
}
