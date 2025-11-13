//go:build linux

// cmd/upgrade/kvm.go
package upgrade

import (
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	kvmDryRun         bool
	kvmNoSnapshot     bool
	kvmDeleteSnapshot bool
	kvmSkipUpgrade    bool
	kvmSkipReboot     bool
	kvmAllDrift       bool
	kvmRolling        bool
	kvmBatchSize      int
	kvmWaitBetween    int
	kvmContinueOnErr  bool
	kvmSecurityOnly   bool
)

// KVMCmd represents the 'eos upgrade kvm' command
var KVMCmd = &cobra.Command{
	Use:   "kvm [vm-name...]",
	Short: "Upgrade packages and reboot KVM VMs to resolve QEMU drift",
	Long: `Upgrade packages inside VMs and reboot them to resolve QEMU version drift.

This command performs a complete upgrade cycle:
1. Create snapshot (optional, default: yes)
2. Run apt update && apt upgrade inside the VM
3. Gracefully reboot the VM
4. Verify QEMU drift resolved
5. Clean up snapshot (optional)

SAFETY FEATURES:
- Snapshots before upgrade (use --no-snapshot to disable)
- Graceful shutdown with timeout
- Rollback capability via snapshots
- Sequential processing to limit blast radius
- Detailed logging and progress tracking

QEMU DRIFT:
After host system updates QEMU, running VMs continue using old binaries.
This causes the "VM guests are running outdated hypervisor" message.
Rebooting VMs picks up the new QEMU version from the host.

EXAMPLES:
  # Upgrade and reboot a single VM
  sudo eos upgrade kvm centos-stream9

  # Dry-run (show what would happen)
  sudo eos upgrade kvm centos-stream9 --dry-run

  # Upgrade all VMs with drift (rolling, batch size 2)
  sudo eos upgrade kvm --all-drift --rolling --batch-size=2

  # Just reboot (skip package upgrade)
  sudo eos upgrade kvm centos-stream9 --skip-upgrade

  # Just upgrade packages (skip reboot)
  sudo eos upgrade kvm centos-stream9 --skip-reboot

  # Security updates only
  sudo eos upgrade kvm --all-drift --security-only`,

	RunE: eos.Wrap(runUpgradeKVM),
}

func init() {
	KVMCmd.Flags().BoolVar(&kvmDryRun, "dry-run", false, "Show what would be done without doing it")
	KVMCmd.Flags().BoolVar(&kvmNoSnapshot, "no-snapshot", false, "Skip snapshot creation (dangerous!)")
	KVMCmd.Flags().BoolVar(&kvmDeleteSnapshot, "delete-snapshot", false, "Delete snapshot after successful upgrade")
	KVMCmd.Flags().BoolVar(&kvmSkipUpgrade, "skip-upgrade", false, "Skip package upgrade, just reboot")
	KVMCmd.Flags().BoolVar(&kvmSkipReboot, "skip-reboot", false, "Skip reboot, just upgrade packages")
	KVMCmd.Flags().BoolVar(&kvmAllDrift, "all-drift", false, "Upgrade all VMs with QEMU drift")
	KVMCmd.Flags().BoolVar(&kvmRolling, "rolling", false, "Rolling upgrade mode")
	KVMCmd.Flags().IntVar(&kvmBatchSize, "batch-size", 1, "VMs to upgrade in each batch")
	KVMCmd.Flags().IntVar(&kvmWaitBetween, "wait-between", 30, "Wait time between batches (seconds)")
	KVMCmd.Flags().BoolVar(&kvmContinueOnErr, "continue-on-error", false, "Continue with other VMs if one fails")
	KVMCmd.Flags().BoolVar(&kvmSecurityOnly, "security-only", false, "Only install security updates (Ubuntu)")

	UpgradeCmd.AddCommand(KVMCmd)
}

func runUpgradeKVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build configuration
	cfg := kvm.DefaultUpgradeAndRebootConfig()
	cfg.DryRun = kvmDryRun
	cfg.CreateSnapshot = !kvmNoSnapshot
	cfg.DeleteSnapshot = kvmDeleteSnapshot
	cfg.SkipUpgrade = kvmSkipUpgrade
	cfg.SkipReboot = kvmSkipReboot
	cfg.ContinueOnError = kvmContinueOnErr

	// Package config
	cfg.PackageConfig.SecurityOnly = kvmSecurityOnly
	cfg.PackageConfig.DryRun = kvmDryRun

	logger.Info("KVM upgrade configuration",
		zap.Bool("dry_run", cfg.DryRun),
		zap.Bool("create_snapshot", cfg.CreateSnapshot),
		zap.Bool("skip_upgrade", cfg.SkipUpgrade),
		zap.Bool("skip_reboot", cfg.SkipReboot))

	// Handle --all-drift flag
	if kvmAllDrift {
		logger.Info("Upgrading all VMs with QEMU drift",
			zap.Bool("rolling", kvmRolling),
			zap.Int("batch_size", kvmBatchSize))

		// Confirm if not rolling
		if !kvmRolling && !kvmDryRun {
			fmt.Printf("⚠ WARNING: Upgrading all VMs with drift simultaneously!\n")
			fmt.Printf("  This will upgrade and reboot multiple VMs at once.\n")
			fmt.Print("Continue? (yes/no): ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "yes" && response != "y" {
				fmt.Println("Cancelled")
				return nil
			}
		}

		waitBetween := time.Duration(kvmWaitBetween) * time.Second
		results, err := kvm.UpgradeAndRebootVMsWithDrift(rc, cfg, kvmRolling, kvmBatchSize, waitBetween)

		kvm.PrintUpgradeResults(results)

		return err
	}

	// Upgrade specific VMs
	if len(args) == 0 {
		return fmt.Errorf("no VMs specified (use --all-drift to upgrade all VMs with drift)")
	}

	// Handle multiple VMs
	if len(args) > 1 {
		logger.Info("Upgrading multiple VMs",
			zap.Int("count", len(args)),
			zap.Bool("rolling", kvmRolling))

		if !kvmRolling && !kvmDryRun {
			fmt.Printf("⚠ WARNING: Upgrading %d VMs simultaneously!\n", len(args))
			fmt.Print("Continue? (yes/no): ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "yes" && response != "y" {
				fmt.Println("Cancelled")
				return nil
			}
		}

		waitBetween := time.Duration(kvmWaitBetween) * time.Second
		results, err := kvm.UpgradeAndRebootMultiple(rc, args, cfg, kvmRolling, kvmBatchSize, waitBetween)

		kvm.PrintUpgradeResults(results)

		return err
	}

	// Single VM upgrade
	vmName := args[0]

	logger.Info("Upgrading VM", zap.String("vm", vmName))

	if cfg.DryRun {
		fmt.Printf("DRY-RUN: Would upgrade and reboot VM: %s\n", vmName)
		if cfg.CreateSnapshot {
			fmt.Println("  1. Create snapshot")
		}
		if !cfg.SkipUpgrade {
			fmt.Println("  2. Run apt update && apt upgrade")
		}
		if !cfg.SkipReboot {
			fmt.Println("  3. Gracefully reboot VM")
		}
		fmt.Println("  4. Verify QEMU drift resolved")
		return nil
	}

	result, err := kvm.UpgradeAndRebootVM(rc, vmName, cfg)
	if err != nil {
		logger.Error("Failed to upgrade VM", zap.String("vm", vmName), zap.Error(err))
		return err
	}

	kvm.PrintUpgradeResults([]*kvm.UpgradeAndRebootResult{result})

	return nil
}
