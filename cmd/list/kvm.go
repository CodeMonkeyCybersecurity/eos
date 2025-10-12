//go:build linux

// cmd/list/kvm.go
// List KVM/QEMU virtual machines with drift detection

package list

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	kvmShowDrift bool
	kvmShowUsage bool
	kvmDetailed  bool
	kvmFormat    string
	kvmState     string
)

var kvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "List KVM/QEMU virtual machines",
	Long: `List all KVM/QEMU VMs with status and drift detection.

This command connects to libvirt and retrieves information about all VMs,
including their state, resource allocation, and QEMU version information.

QEMU DRIFT DETECTION:
When a host system updates QEMU packages, running VMs continue using the
old QEMU version until restarted. This "drift" can be a security concern.
Use --show-drift to identify VMs that need restarting.

EXAMPLES:
  # List all VMs
  eos list kvm

  # Show QEMU version drift
  eos list kvm --show-drift

  # Filter by state
  eos list kvm --state=running

  # Detailed output
  eos list kvm --detailed

  # JSON output for scripting
  eos list kvm --format=json`,

	RunE: eos_cli.Wrap(runListKVM),
}

func init() {
	ListCmd.AddCommand(kvmCmd)

	kvmCmd.Flags().BoolVar(&kvmShowDrift, "show-drift", false, "Show QEMU version drift")
	kvmCmd.Flags().BoolVar(&kvmShowUsage, "show-usage", false, "Show resource usage (CPU, memory, disk)")
	kvmCmd.Flags().BoolVar(&kvmDetailed, "detailed", false, "Show detailed information")
	kvmCmd.Flags().StringVar(&kvmFormat, "format", "table", "Output format (table, json, yaml)")
	kvmCmd.Flags().StringVar(&kvmState, "state", "", "Filter by state (running, shutoff, paused)")
}

func runListKVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing KVM virtual machines",
		zap.Bool("show_drift", kvmShowDrift),
		zap.String("filter_state", kvmState),
		zap.String("format", kvmFormat))

	// Get all VMs
	vms, err := kvm.ListVMs(rc)
	if err != nil {
		logger.Error("Failed to list VMs", zap.Error(err))
		return fmt.Errorf("failed to list VMs: %w", err)
	}

	// Filter by state if specified
	if kvmState != "" {
		vms = kvm.FilterVMsByState(vms, kvmState)
		logger.Info("Filtered VMs by state",
			zap.String("state", kvmState),
			zap.Int("count", len(vms)))
	}

	if len(vms) == 0 {
		logger.Info("No VMs found")
		fmt.Println("No VMs found")
		return nil
	}

	// Output based on format
	switch kvmFormat {
	case "json":
		return outputJSONKVM(vms)
	case "yaml":
		return outputYAMLKVM(vms)
	default:
		return outputTableKVM(vms, kvmShowDrift, kvmShowUsage, kvmDetailed)
	}
}

func outputTableKVM(vms []kvm.VMInfo, showDrift, showUsage, detailed bool) error {
	table := tablewriter.NewWriter(os.Stdout)

	if showUsage {
		table.Header("NAME", "STATE", "LOAD", "MEM_USED", "MEM_TOTAL", "DISK_USED", "DISK_TOTAL", "IPS")

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

			ips := "N/A"
			if len(vm.NetworkIPs) > 0 {
				ips = vm.NetworkIPs[0]
				if len(vm.NetworkIPs) > 1 {
					ips += fmt.Sprintf(" (+%d)", len(vm.NetworkIPs)-1)
				}
			}

			table.Append(
				vm.Name,
				vm.State,
				loadAvg,
				memUsed,
				memTotal,
				diskUsed,
				diskTotal,
				ips,
			)
		}
	} else if showDrift {
		table.Header("NAME", "STATE", "QEMU", "HOST_QEMU", "DRIFT", "UPTIME", "IPS")

		for _, vm := range vms {
			drift := "NO"
			if vm.DriftDetected {
				drift = "YES"
			}

			ips := "N/A"
			if len(vm.NetworkIPs) > 0 {
				ips = vm.NetworkIPs[0]
				if len(vm.NetworkIPs) > 1 {
					ips += fmt.Sprintf(" (+%d)", len(vm.NetworkIPs)-1)
				}
			}

			qemuVer := vm.QEMUVersion
			if qemuVer == "" {
				qemuVer = "N/A"
			}

			hostVer := vm.HostQEMUVersion
			if hostVer == "" {
				hostVer = "N/A"
			}

			table.Append(
				vm.Name,
				vm.State,
				qemuVer,
				hostVer,
				drift,
				fmt.Sprintf("%dd", vm.UptimeDays),
				ips,
			)
		}
	} else {
		table.Header("NAME", "STATE", "VCPUS", "OS", "MEM", "DISK", "CONSUL", "UPDATES", "IPS")

		for _, vm := range vms {
			consul := "N/A"
			if vm.GuestAgentOK {
				consul = vm.ConsulAgent
			}

			updates := "N/A"
			if vm.GuestAgentOK {
				updates = vm.UpdatesNeeded
			}

			ips := "N/A"
			if len(vm.NetworkIPs) > 0 {
				ips = vm.NetworkIPs[0]
				if len(vm.NetworkIPs) > 1 {
					ips += fmt.Sprintf(" (+%d)", len(vm.NetworkIPs)-1)
				}
			}

			osInfo := "N/A"
			if vm.OSInfo != "" {
				osInfo = vm.OSInfo
			}

			memInfo := "N/A"
			if vm.State == "running" && vm.MemoryUsageMB > 0 && vm.MemoryMB > 0 {
				memInfo = fmt.Sprintf("%d/%d MB", vm.MemoryUsageMB, vm.MemoryMB)
			} else if vm.MemoryMB > 0 {
				memInfo = fmt.Sprintf("%d MB", vm.MemoryMB)
			}

			// Format disk with usage percentage if available
			diskInfo := "N/A"
			if vm.DiskSizeGB > 0 {
				if vm.DiskUsageGB > 0 && vm.DiskTotalGB > 0 {
					// Show guest filesystem usage
					usagePercent := float64(vm.DiskUsageGB) / float64(vm.DiskTotalGB) * 100
					diskInfo = fmt.Sprintf("%d GB (%.0f%%)", vm.DiskTotalGB, usagePercent)
				} else {
					// Show allocated disk image size only
					diskInfo = fmt.Sprintf("%d GB", vm.DiskSizeGB)
				}
			}

			// Format VCPUS with CPU% if available
			vcpuInfo := fmt.Sprintf("%d", vm.VCPUs)
			if vm.State == "running" && vm.CPUUsagePercent > 0 {
				vcpuInfo = fmt.Sprintf("%d (%.0f%%)", vm.VCPUs, vm.CPUUsagePercent)
			}

			// Format MEM with percentage if usage is available
			memInfoFormatted := memInfo
			if vm.State == "running" && vm.MemoryUsageMB > 0 && vm.MemoryMB > 0 {
				usagePercent := float64(vm.MemoryUsageMB) / float64(vm.MemoryMB) * 100
				memInfoFormatted = fmt.Sprintf("%d MB (%.0f%%)", vm.MemoryMB, usagePercent)
			}

			table.Append(
				vm.Name,
				vm.State,
				vcpuInfo,
				osInfo,
				memInfoFormatted,
				diskInfo,
				consul,
				updates,
				ips,
			)
		}
	}

	table.Render()

	// Show summary
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
		fmt.Println("  eos update kvm <vm-name> --enable-guest-exec")
		fmt.Println()
		fmt.Println("Or to fix all at once:")
		for _, vmName := range disabledVMs {
			fmt.Printf("  eos update kvm %s --enable-guest-exec\n", vmName)
		}
	}

	return nil
}

func outputJSONKVM(vms []kvm.VMInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(vms)
}

func outputYAMLKVM(vms []kvm.VMInfo) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer func() { _ = encoder.Close() }()
	return encoder.Encode(vms)
}
