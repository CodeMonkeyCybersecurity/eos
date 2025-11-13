//go:build linux

// cmd/list/kvm.go
// List KVM/QEMU virtual machines with drift detection

package list

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
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

	// Build output configuration and delegate to pkg
	outputConfig := &kvm.OutputConfig{
		Format:    kvmFormat,
		ShowDrift: kvmShowDrift,
		ShowUsage: kvmShowUsage,
		Detailed:  kvmDetailed,
	}

	return kvm.OutputVMs(vms, outputConfig)
}
