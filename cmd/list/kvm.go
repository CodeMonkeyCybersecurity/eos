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
	vms, err := kvm.ListVMs(rc.Ctx)
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
		return outputTableKVM(vms, kvmShowDrift, kvmDetailed)
	}
}

func outputTableKVM(vms []kvm.VMInfo, showDrift, detailed bool) error {
	table := tablewriter.NewWriter(os.Stdout)

	if showDrift {
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
		table.Header("NAME", "STATE", "VCPUS", "MEMORY", "GUEST_AGENT", "IPS")

		for _, vm := range vms {
			agent := "NO"
			if vm.GuestAgentOK {
				agent = "YES"
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
				fmt.Sprintf("%d", vm.VCPUs),
				fmt.Sprintf("%d MB", vm.MemoryMB),
				agent,
				ips,
			)
		}
	}

	table.Render()

	// Show summary
	driftCount := 0
	for _, vm := range vms {
		if vm.DriftDetected {
			driftCount++
		}
	}

	fmt.Printf("\nTotal VMs: %d", len(vms))
	if showDrift && driftCount > 0 {
		fmt.Printf(" (⚠ %d with QEMU drift)", driftCount)
	}
	fmt.Println()

	return nil
}

func outputJSONKVM(vms []kvm.VMInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(vms)
}

func outputYAMLKVM(vms []kvm.VMInfo) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer encoder.Close()
	return encoder.Encode(vms)
}
