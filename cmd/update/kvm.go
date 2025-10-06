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

// rescueKvmCmd represents the 'eos rescue kvm' command.
var rescueKvmCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Rescue a KVM virtual machine (shutdown & open virt-rescue shell)",
	Long: `This command shuts down the specified KVM/libvirt virtual machine if it's running, 
waits for it to stop, and then opens a virt-rescue shell so you can troubleshoot it.
Example:
  eos rescue kvm --name centos-stream9-2
`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Grab the flag
		vmName, _ := cmd.Flags().GetString("name")
		if vmName == "" {
			return fmt.Errorf(" You must provide a --name (the libvirt/KVM domain name)")
		}

		log := otelzap.Ctx(rc.Ctx)
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
	kvmSafe         bool
	kvmNoSafe       bool
	kvmSnapshot     bool
	kvmSnapshotName string
	kvmTimeout      int
	kvmAllDrift     bool
	kvmRolling      bool
	kvmBatchSize    int
	kvmWaitBetween  int
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
			fmt.Scanln(&response)
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
			fmt.Scanln(&response)
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

func init() {
	// Add the kvm subcommand to the parent 'refresh' command
	rescueKvmCmd.Flags().String("name", "", "Domain name of the KVM virtual machine (required)")
	_ = rescueKvmCmd.MarkFlagRequired("name")

	UpdateCmd.AddCommand(rescueKvmCmd)

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
}
