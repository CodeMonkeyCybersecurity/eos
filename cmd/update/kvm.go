//go:build linux

// cmd/update/kvm.go
package update

import (
	"fmt"
	"time"

	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// updateKvmCmd represents the 'eos update kvm' command.
var updateKvmCmd = &cobra.Command{
	Use:   "kvm [vm-name]",
	Short: "Update a KVM virtual machine (shutdown & open virt-rescue shell)",
	Args:  cobra.MaximumNArgs(1),
	Long: `This command shuts down the specified KVM/libvirt virtual machine if it's running,
waits for it to stop, and then opens a virt-rescue shell so you can troubleshoot it.

FLAGS:
  --enable-guest-exec    Enable QEMU guest agent guest-exec commands for monitoring
  --all-disabled         Enable guest-exec for all VMs with DISABLED status (requires --enable-guest-exec)
  --yes                  Skip confirmation prompt for bulk operations

Example:
  eos update kvm centos-stream9-2
  eos update kvm centos-stream9-2 --enable-guest-exec
  eos update kvm --enable-guest-exec --all-disabled
  eos update kvm --enable-guest-exec --all-disabled --yes
`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		// Handle --enable-guest-exec flag
		if kvmEnableGuestExec {
			// Handle bulk operation
			if kvmAllDisabledGuestExec {
				return kvm.EnableGuestExecBulk(rc, kvmYesConfirm)
			}

			// Single VM operation
			if len(args) == 0 {
				return fmt.Errorf("VM name required (or use --all-disabled for bulk operation)")
			}

			vmName := args[0]
			log.Info("Enabling guest-exec for VM", zap.String("vm", vmName))
			return kvm.EnableGuestExec(rc, vmName)
		}

		// Rescue mode requires VM name
		if len(args) == 0 {
			return fmt.Errorf("VM name required")
		}

		vmName := args[0]

		log.Info("🛠 Starting rescue for KVM VM", zap.String("vm", vmName))

		// Check VM status
		state, err := kvm.GetDomainState(rc.Ctx, vmName)
		if err != nil {
			return fmt.Errorf("failed to get VM state: %w", err)
		}

		if state == "shutoff" {
			log.Info(" VM is already shut off", zap.String("vm", vmName))
		} else {
			// Shut it down
			log.Info("Shutting down VM...", zap.String("vm", vmName))
			if err := kvm.ShutdownDomain(rc.Ctx, vmName); err != nil {
				return fmt.Errorf("failed to shutdown VM: %w", err)
			}

			// Wait for shutdown (up to 5 minutes)
			log.Info(" Waiting for VM to shut off...")
			for i := 0; i < 100; i++ {
				time.Sleep(3 * time.Second)
				state, err := kvm.GetDomainState(rc.Ctx, vmName)
				if err != nil {
					return fmt.Errorf("failed to get VM state: %w", err)
				}
				if state == "shutoff" {
					log.Info(" VM is now shut off", zap.String("vm", vmName))
					break
				}
				log.Debug("...still waiting for VM to shut off")
			}
		}

		// Launch virt-rescue
		log.Info(" Launching virt-rescue shell (requires sudo)", zap.String("vm", vmName))
		cmdRescue := exec.Command("sudo", "virt-rescue", "-d", vmName)
		cmdRescue.Stdout = os.Stdout
		cmdRescue.Stderr = os.Stderr
		cmdRescue.Stdin = os.Stdin
		if err := cmdRescue.Run(); err != nil {
			return fmt.Errorf("virt-rescue failed: %w", err)
		}

		log.Info(" Rescue session completed")
		return nil
	}),
}

var (
	kvmSafe                 bool
	kvmNoSafe               bool
	kvmSnapshot             bool
	kvmSnapshotName         string
	kvmTimeout              int
	kvmAllDrift             bool
	kvmRolling              bool
	kvmBatchSize            int
	kvmWaitBetween          int
	kvmEnableGuestExec      bool
	kvmAllDisabledGuestExec bool
	kvmYesConfirm           bool
)

// restartKvmCmd represents safe VM restart command
var restartKvmCmd = &cobra.Command{
	Use:   "kvm-restart [vm-name...]",
	Short: "Safely restart KVM virtual machines",
	Long: `Safely restart KVM/QEMU virtual machines with health checks and drift resolution.

This command performs graceful VM restarts with pre-flight and post-flight checks
to ensure VMs come back up successfully. It's particularly useful for resolving
QEMU version drift after host system updates.

SAFETY CHECKS:
- Verify VM is running before restart
- Check guest agent responsiveness (if available)
- Graceful ACPI shutdown with timeout
- Force shutdown only if graceful fails
- Verify VM starts successfully
- Validate network and guest agent after boot

QEMU DRIFT:
When the host system updates QEMU, running VMs continue using the old version
until restarted. Use --all-drift to automatically restart all VMs with drift.

EXAMPLES:
  # Restart a single VM (safe mode by default)
  eos update kvm-restart centos-stream9-3
  eos restart kvm-restart centos-stream9-3    # alias

  # Restart with snapshot (rollback on failure)
  eos restart kvm-restart centos-stream9-3 --snapshot

  # Skip safety checks (dangerous!)
  eos restart kvm-restart centos-stream9-3 --no-safe

  # Restart multiple VMs
  eos restart kvm-restart vm1 vm2 vm3

  # Restart all VMs with QEMU drift
  eos restart kvm-restart --all-drift

  # Rolling restart with batches
  eos restart kvm-restart --all-drift --rolling --batch-size=2 --wait-between=30`,

	RunE: eos.Wrap(runRestartKVM),
}

func runRestartKVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build restart configuration
	cfg := kvm.DefaultRestartConfig()
	cfg.SkipSafetyChecks = kvmNoSafe
	cfg.CreateSnapshot = kvmSnapshot
	cfg.ShutdownTimeout = time.Duration(kvmTimeout) * time.Second

	if kvmSnapshotName != "" {
		cfg.SnapshotName = kvmSnapshotName
	}

	logger.Info("KVM restart configuration",
		zap.Bool("safe_mode", !cfg.SkipSafetyChecks),
		zap.Bool("snapshot", cfg.CreateSnapshot),
		zap.Duration("timeout", cfg.ShutdownTimeout))

	// Handle --all-drift flag
	if kvmAllDrift {
		logger.Info("Restarting all VMs with QEMU drift",
			zap.Bool("rolling", kvmRolling),
			zap.Int("batch_size", kvmBatchSize))

		// Confirm if not in rolling mode
		if !kvmRolling {
			fmt.Println("⚠ WARNING: Restarting all VMs with drift simultaneously may cause service disruption!")
			fmt.Print("Continue? (yes/no): ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "yes" && response != "y" {
				fmt.Println("Cancelled")
				return nil
			}
		}

		waitBetween := time.Duration(kvmWaitBetween) * time.Second
		return kvm.RestartVMsWithDrift(rc.Ctx, cfg, kvmRolling, kvmBatchSize, waitBetween)
	}

	// Restart specific VMs
	if len(args) == 0 {
		return fmt.Errorf("no VMs specified (use --all-drift to restart all VMs with drift)")
	}

	// Handle multiple VMs
	if len(args) > 1 {
		logger.Info("Restarting multiple VMs",
			zap.Int("count", len(args)),
			zap.Bool("rolling", kvmRolling))

		if !kvmRolling {
			fmt.Printf("⚠ WARNING: Restarting %d VMs simultaneously!\n", len(args))
			fmt.Print("Continue? (yes/no): ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "yes" && response != "y" {
				fmt.Println("Cancelled")
				return nil
			}
		}

		waitBetween := time.Duration(kvmWaitBetween) * time.Second
		return kvm.RestartMultipleVMs(rc.Ctx, args, cfg, kvmRolling, kvmBatchSize, waitBetween)
	}

	// Single VM restart
	vmName := args[0]

	logger.Info("Restarting VM", zap.String("vm", vmName))

	// Show warning if no snapshot and not skipping safety
	if !cfg.CreateSnapshot && !cfg.SkipSafetyChecks {
		fmt.Println("ℹ Tip: Use --snapshot to create a safety snapshot before restart")
	}

	if err := kvm.RestartVM(rc.Ctx, vmName, cfg); err != nil {
		logger.Error("Failed to restart VM", zap.String("vm", vmName), zap.Error(err))
		return err
	}

	fmt.Printf(" VM %s restarted successfully\n", vmName)
	return nil
}

var (
	upgradeKvmDryRun         bool
	upgradeKvmNoSnapshot     bool
	upgradeKvmDeleteSnapshot bool
	upgradeKvmSkipUpgrade    bool
	upgradeKvmSkipReboot     bool
	upgradeKvmAllDrift       bool
	upgradeKvmRolling        bool
	upgradeKvmBatchSize      int
	upgradeKvmWaitBetween    int
	upgradeKvmContinueOnErr  bool
	upgradeKvmSecurityOnly   bool
)

// upgradeKvmCmd represents the 'eos update kvm-upgrade' command
var upgradeKvmCmd = &cobra.Command{
	Use:   "kvm-upgrade [vm-name...]",
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
  sudo eos update kvm-upgrade centos-stream9

  # Dry-run (show what would happen)
  sudo eos update kvm-upgrade centos-stream9 --dry-run

  # Upgrade all VMs with drift (rolling, batch size 2)
  sudo eos update kvm-upgrade --all-drift --rolling --batch-size=2

  # Just reboot (skip package upgrade)
  sudo eos update kvm-upgrade centos-stream9 --skip-upgrade

  # Just upgrade packages (skip reboot)
  sudo eos update kvm-upgrade centos-stream9 --skip-reboot

  # Security updates only
  sudo eos update kvm-upgrade --all-drift --security-only`,

	RunE: eos.Wrap(runUpgradeKVM),
}

func runUpgradeKVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build configuration
	cfg := kvm.DefaultUpgradeAndRebootConfig()
	cfg.DryRun = upgradeKvmDryRun
	cfg.CreateSnapshot = !upgradeKvmNoSnapshot
	cfg.DeleteSnapshot = upgradeKvmDeleteSnapshot
	cfg.SkipUpgrade = upgradeKvmSkipUpgrade
	cfg.SkipReboot = upgradeKvmSkipReboot
	cfg.ContinueOnError = upgradeKvmContinueOnErr

	// Package config
	cfg.PackageConfig.SecurityOnly = upgradeKvmSecurityOnly
	cfg.PackageConfig.DryRun = upgradeKvmDryRun

	logger.Info("KVM upgrade configuration",
		zap.Bool("dry_run", cfg.DryRun),
		zap.Bool("create_snapshot", cfg.CreateSnapshot),
		zap.Bool("skip_upgrade", cfg.SkipUpgrade),
		zap.Bool("skip_reboot", cfg.SkipReboot))

	// Handle --all-drift flag
	if upgradeKvmAllDrift {
		logger.Info("Upgrading all VMs with QEMU drift",
			zap.Bool("rolling", upgradeKvmRolling),
			zap.Int("batch_size", upgradeKvmBatchSize))

		// Confirm if not rolling
		if !upgradeKvmRolling && !upgradeKvmDryRun {
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

		waitBetween := time.Duration(upgradeKvmWaitBetween) * time.Second
		results, err := kvm.UpgradeAndRebootVMsWithDrift(rc, cfg, upgradeKvmRolling, upgradeKvmBatchSize, waitBetween)

		printUpgradeResults(results)

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
			zap.Bool("rolling", upgradeKvmRolling))

		if !upgradeKvmRolling && !upgradeKvmDryRun {
			fmt.Printf("⚠ WARNING: Upgrading %d VMs simultaneously!\n", len(args))
			fmt.Print("Continue? (yes/no): ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "yes" && response != "y" {
				fmt.Println("Cancelled")
				return nil
			}
		}

		waitBetween := time.Duration(upgradeKvmWaitBetween) * time.Second
		results, err := kvm.UpgradeAndRebootMultiple(rc, args, cfg, upgradeKvmRolling, upgradeKvmBatchSize, waitBetween)

		printUpgradeResults(results)

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

	printUpgradeResults([]*kvm.UpgradeAndRebootResult{result})

	return nil
}

// printUpgradeResults displays a summary of upgrade operations
func printUpgradeResults(results []*kvm.UpgradeAndRebootResult) {
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

func init() {
	// Add the kvm subcommand to the parent 'update' command
	UpdateCmd.AddCommand(updateKvmCmd)
	updateKvmCmd.Flags().BoolVar(&kvmEnableGuestExec, "enable-guest-exec", false, "Enable QEMU guest agent guest-exec commands")
	updateKvmCmd.Flags().BoolVar(&kvmAllDisabledGuestExec, "all-disabled", false, "Enable guest-exec for all VMs with DISABLED status")
	updateKvmCmd.Flags().BoolVar(&kvmYesConfirm, "yes", false, "Skip confirmation prompt for bulk operations")

	// Add restart kvm command
	restartKvmCmd.Flags().BoolVar(&kvmSafe, "safe", true, "Enable safety checks (default)")
	restartKvmCmd.Flags().BoolVar(&kvmNoSafe, "no-safe", false, "Disable safety checks (dangerous!)")
	restartKvmCmd.Flags().BoolVar(&kvmSnapshot, "snapshot", false, "Create snapshot before restart")
	restartKvmCmd.Flags().StringVar(&kvmSnapshotName, "snapshot-name", "", "Custom snapshot name")
	restartKvmCmd.Flags().IntVar(&kvmTimeout, "timeout", 300, "Shutdown timeout in seconds")
	restartKvmCmd.Flags().BoolVar(&kvmAllDrift, "all-drift", false, "Restart all VMs with QEMU drift")
	restartKvmCmd.Flags().BoolVar(&kvmRolling, "rolling", false, "Rolling restart mode")
	restartKvmCmd.Flags().IntVar(&kvmBatchSize, "batch-size", 1, "VMs to restart in each batch")
	restartKvmCmd.Flags().IntVar(&kvmWaitBetween, "wait-between", 30, "Wait time between batches (seconds)")

	UpdateCmd.AddCommand(restartKvmCmd)

	// Add upgrade kvm command
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmDryRun, "dry-run", false, "Show what would be done without doing it")
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmNoSnapshot, "no-snapshot", false, "Skip snapshot creation (dangerous!)")
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmDeleteSnapshot, "delete-snapshot", false, "Delete snapshot after successful upgrade")
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmSkipUpgrade, "skip-upgrade", false, "Skip package upgrade, just reboot")
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmSkipReboot, "skip-reboot", false, "Skip reboot, just upgrade packages")
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmAllDrift, "all-drift", false, "Upgrade all VMs with QEMU drift")
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmRolling, "rolling", false, "Rolling upgrade mode")
	upgradeKvmCmd.Flags().IntVar(&upgradeKvmBatchSize, "batch-size", 1, "VMs to upgrade in each batch")
	upgradeKvmCmd.Flags().IntVar(&upgradeKvmWaitBetween, "wait-between", 30, "Wait time between batches (seconds)")
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmContinueOnErr, "continue-on-error", false, "Continue with other VMs if one fails")
	upgradeKvmCmd.Flags().BoolVar(&upgradeKvmSecurityOnly, "security-only", false, "Only install security updates (Ubuntu)")

	UpdateCmd.AddCommand(upgradeKvmCmd)
}
