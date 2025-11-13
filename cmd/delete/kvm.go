//go:build linux

// cmd/delete/kvm.go
package delete

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	kvmForce         bool
	kvmRemoveStorage bool
)

// KvmCmd represents the 'eos delete kvm' command (also accessible via 'eos rm kvm')
var KvmCmd = &cobra.Command{
	Use:   "kvm [vm-name]",
	Short: "Delete a KVM virtual machine",
	Args:  cobra.ExactArgs(1),
	Long: `Delete (remove) a KVM/libvirt virtual machine.

This command will:
1. Stop the VM if it's running (with --force)
2. Undefine the VM from libvirt
3. Optionally remove associated storage volumes (with --remove-storage)

Examples:
  # Delete a VM (keeps storage)
  eos delete kvm my-vm
  eos rm kvm my-vm

  # Delete a VM and remove storage
  eos delete kvm my-vm --remove-storage

  # Force delete a running VM
  eos delete kvm my-vm --force --remove-storage`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Detect if user accidentally used '--' separator (e.g., 'eos delete kvm vm-name -- --force')
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}

		vmName := args[0]

		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Deleting KVM virtual machine",
			zap.String("vm", vmName),
			zap.Bool("force", kvmForce),
			zap.Bool("remove_storage", kvmRemoveStorage))

		// Check if VM exists and get state
		state, err := kvm.GetDomainState(rc.Ctx, vmName)
		if err != nil {
			return fmt.Errorf("failed to get VM state: %w", err)
		}

		logger.Info("VM state", zap.String("vm", vmName), zap.String("state", state))

		// If VM is running, destroy it first (if --force is set)
		if state != "shutoff" {
			if !kvmForce {
				return fmt.Errorf("VM is running (state: %s). Use --force to stop and delete", state)
			}

			logger.Info("Stopping VM forcefully", zap.String("vm", vmName))
			if err := kvm.DestroyDomain(rc.Ctx, vmName); err != nil {
				return fmt.Errorf("failed to stop VM: %w", err)
			}
			logger.Info("VM stopped", zap.String("vm", vmName))
		}

		// Undefine (delete) the VM
		logger.Info("Undefining VM from libvirt",
			zap.String("vm", vmName),
			zap.Bool("remove_storage", kvmRemoveStorage))

		if err := kvm.UndefineDomain(rc.Ctx, vmName, kvmRemoveStorage); err != nil {
			return fmt.Errorf("failed to undefine VM: %w", err)
		}

		logger.Info("VM deleted successfully", zap.String("vm", vmName))

		if kvmRemoveStorage {
			logger.Info("Associated storage volumes removed", zap.String("vm", vmName))
		} else {
			logger.Info("Storage volumes preserved (use --remove-storage to delete)", zap.String("vm", vmName))
		}

		return nil
	}),
}

func init() {
	KvmCmd.Flags().BoolVar(&kvmForce, "force", false, "Force delete even if VM is running")
	KvmCmd.Flags().BoolVar(&kvmRemoveStorage, "remove-storage", false, "Remove associated storage volumes")

	DeleteCmd.AddCommand(KvmCmd)
}
