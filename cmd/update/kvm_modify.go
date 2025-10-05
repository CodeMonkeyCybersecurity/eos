// cmd/update/kvm_modify.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	kvmMemory    string
	kvmCPUs      string
	kvmAutostart *bool
	kvmStart     bool
	kvmStop      bool
	kvmRestart   bool
)

// KvmModifyCmd represents the 'eos update kvm' command
var KvmModifyCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Update/modify a KVM virtual machine configuration",
	Long: `Update or modify configuration of an existing KVM virtual machine.

This command allows you to change various VM properties such as:
- Memory allocation
- CPU count
- Autostart behavior
- Power state (start/stop/restart)

Examples:
  # Change VM memory to 4GB
  eos update kvm --vmname my-vm --memory 4G

  # Change CPU count to 4 cores
  eos update kvm --vmname my-vm --cpus 4

  # Enable autostart
  eos update kvm --vmname my-vm --autostart

  # Disable autostart
  eos update kvm --vmname my-vm --no-autostart

  # Start a VM
  eos update kvm --vmname my-vm --start

  # Stop a VM
  eos update kvm --vmname my-vm --stop

  # Restart a VM
  eos update kvm --vmname my-vm --restart

  # Combine multiple changes
  eos update kvm --vmname my-vm --memory 8G --cpus 4 --autostart --restart`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		vmName, _ := cmd.Flags().GetString("vmname")
		if vmName == "" {
			return fmt.Errorf("--vmname is required")
		}

		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Updating KVM virtual machine", zap.String("vm", vmName))

		// Check if VM exists
		state, err := kvm.GetDomainState(rc.Ctx, vmName)
		if err != nil {
			return fmt.Errorf("failed to get VM state: %w", err)
		}

		logger.Info("Current VM state", zap.String("vm", vmName), zap.String("state", state))

		// Track if any changes were made
		changesMade := false

		// Handle memory change
		if kvmMemory != "" {
			logger.Info("Memory change requested (requires VM config update)",
				zap.String("vm", vmName),
				zap.String("new_memory", kvmMemory))
			logger.Warn("Memory change requires virsh edit or XML manipulation - not yet implemented")
			logger.Info("Manual steps: virsh edit " + vmName + " and modify <memory> and <currentMemory> tags")
			// TODO: Implement XML manipulation for memory
		}

		// Handle CPU change
		if kvmCPUs != "" {
			logger.Info("CPU change requested (requires VM config update)",
				zap.String("vm", vmName),
				zap.String("new_cpus", kvmCPUs))
			logger.Warn("CPU change requires virsh edit or XML manipulation - not yet implemented")
			logger.Info("Manual steps: virsh edit " + vmName + " and modify <vcpu> tag")
			// TODO: Implement XML manipulation for CPUs
		}

		// Handle autostart change
		if kvmAutostart != nil {
			logger.Info("Setting VM autostart",
				zap.String("vm", vmName),
				zap.Bool("autostart", *kvmAutostart))

			if err := kvm.SetDomainAutostart(rc.Ctx, vmName, *kvmAutostart); err != nil {
				return fmt.Errorf("failed to set autostart: %w", err)
			}

			logger.Info("Autostart updated", zap.String("vm", vmName), zap.Bool("autostart", *kvmAutostart))
			changesMade = true
		}

		// Handle power state changes (mutually exclusive)
		powerActions := 0
		if kvmStart {
			powerActions++
		}
		if kvmStop {
			powerActions++
		}
		if kvmRestart {
			powerActions++
		}

		if powerActions > 1 {
			return fmt.Errorf("only one power action allowed: --start, --stop, or --restart")
		}

		// Start VM
		if kvmStart {
			if state == "running" {
				logger.Info("VM already running", zap.String("vm", vmName))
			} else {
				logger.Info("Starting VM", zap.String("vm", vmName))
				if err := kvm.StartDomain(rc.Ctx, vmName); err != nil {
					return fmt.Errorf("failed to start VM: %w", err)
				}
				logger.Info("VM started", zap.String("vm", vmName))
				changesMade = true
			}
		}

		// Stop VM
		if kvmStop {
			if state == "shutoff" {
				logger.Info("VM already stopped", zap.String("vm", vmName))
			} else {
				logger.Info("Stopping VM", zap.String("vm", vmName))
				if err := kvm.ShutdownDomain(rc.Ctx, vmName); err != nil {
					return fmt.Errorf("failed to stop VM: %w", err)
				}
				logger.Info("VM stopped", zap.String("vm", vmName))
				changesMade = true
			}
		}

		// Restart VM
		if kvmRestart {
			logger.Info("Restarting VM", zap.String("vm", vmName))

			// Use the safe restart function if available
			cfg := kvm.DefaultRestartConfig()
			if err := kvm.RestartVM(rc.Ctx, vmName, cfg); err != nil {
				return fmt.Errorf("failed to restart VM: %w", err)
			}

			logger.Info("VM restarted", zap.String("vm", vmName))
			changesMade = true
		}

		if !changesMade {
			logger.Warn("No changes specified",
				zap.String("hint", "Use --memory, --cpus, --autostart, --start, --stop, or --restart"))
			return fmt.Errorf("no changes requested")
		}

		logger.Info("VM update completed", zap.String("vm", vmName))
		return nil
	}),
}

func init() {
	KvmModifyCmd.Flags().String("vmname", "", "Name of the VM to update (required)")
	KvmModifyCmd.Flags().StringVar(&kvmMemory, "memory", "", "New memory allocation (e.g., 4G, 8192M)")
	KvmModifyCmd.Flags().StringVar(&kvmCPUs, "cpus", "", "New CPU count (e.g., 2, 4)")

	// Use custom flag for autostart to detect if it was set
	autostartTrue := KvmModifyCmd.Flags().Bool("autostart", false, "Enable autostart")
	autostartFalse := KvmModifyCmd.Flags().Bool("no-autostart", false, "Disable autostart")

	// Handle autostart flags in PreRunE
	KvmModifyCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("autostart") && cmd.Flags().Changed("no-autostart") {
			return fmt.Errorf("cannot use both --autostart and --no-autostart")
		}
		if cmd.Flags().Changed("autostart") {
			val := true
			kvmAutostart = &val
		} else if cmd.Flags().Changed("no-autostart") {
			val := false
			kvmAutostart = &val
		}

		// Store flag values
		if autostartTrue != nil && *autostartTrue {
			// Already handled above
		}
		if autostartFalse != nil && *autostartFalse {
			// Already handled above
		}

		return nil
	}

	KvmModifyCmd.Flags().BoolVar(&kvmStart, "start", false, "Start the VM")
	KvmModifyCmd.Flags().BoolVar(&kvmStop, "stop", false, "Stop the VM")
	KvmModifyCmd.Flags().BoolVar(&kvmRestart, "restart", false, "Restart the VM")

	_ = KvmModifyCmd.MarkFlagRequired("vmname")

	UpdateCmd.AddCommand(KvmModifyCmd)
}
