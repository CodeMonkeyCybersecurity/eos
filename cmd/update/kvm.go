//go:build linux

// cmd/update/kvm.go
// Orchestration layer for KVM update operations

package update

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Action flags
var (
	kvmAdd     bool
	kvmEnable  bool
	kvmRestart bool
)

// Target flags
var (
	kvmGuestAgent bool
	kvmGuestExec  bool
)

// Selection flags
var (
	kvmName        []string
	kvmAll         bool
	kvmAllDisabled bool
	kvmAllDrift    bool
)

// Modifier flags
var (
	kvmDryRun       bool
	kvmYes          bool
	kvmForce        bool
	kvmBatchSize    int
	kvmWaitBetween  int
	kvmNoBackup     bool
	kvmNoRestart    bool
	kvmNoSafe       bool
	kvmSnapshot     bool
	kvmSnapshotName string
	kvmTimeout      int
	kvmRolling      bool
)

// updateKvmCmd represents the 'eos update kvm' command with unified flag-based interface
var updateKvmCmd = &cobra.Command{
	Use:   "kvm [vm-name]",
	Short: "Update KVM virtual machines (guest agent, guest-exec, restart, rescue)",
	Args:  cobra.MaximumNArgs(1),
	Long: `Update and manage KVM/libvirt virtual machines with a unified flag-based interface.

OPERATIONS (mutually exclusive):
  --add           Add features/configuration to VMs
  --enable        Enable features on VMs
  --restart       Restart VMs safely
  (no flags)      Open virt-rescue shell (requires vm-name)

TARGETS (used with --add or --enable):
  --guest-agent   QEMU guest agent channel (--add) or guest-exec capability (--enable)
  --guest-exec    Guest-exec capability (--enable only)

VM SELECTION:
  --name NAME     Specific VM name (can be repeated: --name vm1 --name vm2)
  --all           All VMs
  --all-disabled  All VMs with guest-exec disabled (--enable only)
  --all-drift     All VMs with QEMU drift (--restart only)

MODIFIERS:
  --dry-run          Preview changes without applying
  --yes, --force     Skip confirmation prompts
  --batch-size N     Process N VMs at a time (default: 3 for add, 1 for restart)
  --wait-between N   Seconds between batches (default: 30)
  --no-backup        Skip XML backups (not recommended)
  --no-restart       Skip restart prompts for running VMs
  --snapshot         Create snapshot before restart
  --no-safe          Skip safety checks for restart (dangerous!)

EXAMPLES:
  # Add guest agent channel to VM XML (hypervisor-side)
  eos update kvm --add --guest-agent --name centos-stream9
  eos update kvm --add --guest-agent --all
  eos update kvm --add --guest-agent --name vm1 --name vm2 --name vm3

  # Enable guest-exec for monitoring
  eos update kvm --enable --guest-exec --name my-vm
  eos update kvm --enable --guest-exec --all-disabled
  eos update kvm --enable --guest-exec --all --yes

  # Restart VMs
  eos update kvm --restart --name my-vm
  eos update kvm --restart --all-drift
  eos update kvm --restart --name my-vm --snapshot

  # Rescue mode (legacy - no flags)
  eos update kvm my-vm

  # Bulk operations with custom batching
  eos update kvm --add --guest-agent --all --batch-size 5 --wait-between 15
  eos update kvm --restart --all-drift --rolling --batch-size 2

  # Dry-run to preview changes
  eos update kvm --add --guest-agent --all --dry-run
  eos update kvm --enable --guest-exec --all-disabled --dry-run`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Count action flags
		actionCount := 0
		if kvmAdd {
			actionCount++
		}
		if kvmEnable {
			actionCount++
		}
		if kvmRestart {
			actionCount++
		}

		// If no action flags, default to rescue mode (legacy behavior)
		if actionCount == 0 {
			return runRescueMode(rc, args)
		}

		// Validate: only one action at a time
		if actionCount > 1 {
			return fmt.Errorf("only one action flag allowed at a time: --add, --enable, or --restart")
		}

		// Route to appropriate handler
		if kvmAdd {
			return runAddOperation(rc)
		}
		if kvmEnable {
			return runEnableOperation(rc)
		}
		if kvmRestart {
			return runRestartOperation(rc)
		}

		return fmt.Errorf("no valid operation specified")
	}),
}

// runAddOperation handles --add operations (orchestration only)
func runAddOperation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate target
	if !kvmGuestAgent {
		return fmt.Errorf("--add requires a target: --guest-agent")
	}

	// Get target VMs
	targetVMs, err := getTargetVMs(rc, false, false)
	if err != nil {
		return err
	}

	if len(targetVMs) == 0 {
		return fmt.Errorf("no VMs specified (use --name, --all, or provide VM names)")
	}

	logger.Info("Adding guest agent channel to VMs",
		zap.Int("vm_count", len(targetVMs)),
		zap.Bool("dry_run", kvmDryRun))

	// Build configuration
	config := &kvm.GuestAgentAddConfig{
		VMNames:     targetVMs,
		DryRun:      kvmDryRun,
		Force:       kvmYes || kvmForce,
		BatchSize:   kvmBatchSize,
		WaitBetween: kvmWaitBetween,
		NoBackup:    kvmNoBackup,
		NoRestart:   kvmNoRestart,
	}

	// Show impact and get confirmation (unless --yes or --force)
	if !config.Force && !config.DryRun {
		if !showImpactAndConfirm(rc, targetVMs) {
			logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Call business logic in pkg
	result, err := kvm.AddGuestAgentToVMs(rc, config)
	if err != nil {
		return err
	}

	// Handle restart prompts for running VMs
	if !kvmNoRestart && !kvmDryRun && len(result.UpdatedVMs) > 0 {
		for _, vmName := range result.UpdatedVMs {
			if kvm.IsVMRunning(rc.Ctx, vmName) {
				logger.Info("")
				logger.Info("VM is running - restart required for guest agent channel to be available",
					zap.String("vm", vmName))
				logger.Info("terminal prompt: Restart VM now?")
				var response string
				fmt.Printf("Restart %s now? (yes/no): ", vmName)
				_, _ = fmt.Scanln(&response)

				if strings.ToLower(response) == "yes" {
					logger.Info("Restarting VM", zap.String("vm", vmName))
					if err := kvm.RestartVM(rc.Ctx, vmName, kvm.DefaultRestartConfig()); err != nil {
						logger.Warn("Failed to restart VM - you can restart manually later", zap.Error(err))
					} else {
						logger.Info("VM restarted successfully", zap.String("vm", vmName))
					}
				} else {
					logger.Info("Skipped restart - remember to restart VM later for changes to take effect")
				}
			}
		}
	}

	return nil
}

// runEnableOperation handles --enable operations (orchestration only)
func runEnableOperation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate target
	if !kvmGuestExec && !kvmGuestAgent {
		return fmt.Errorf("--enable requires a target: --guest-exec or --guest-agent")
	}

	// --guest-agent with --enable is same as --guest-exec
	if kvmGuestAgent {
		kvmGuestExec = true
	}

	// Handle bulk operation for all-disabled
	if kvmAllDisabled {
		logger.Info("Enabling guest-exec for all VMs with DISABLED status")
		return kvm.EnableGuestExecBulk(rc, kvmYes || kvmForce)
	}

	// Get target VMs
	targetVMs, err := getTargetVMs(rc, false, false)
	if err != nil {
		return err
	}

	if len(targetVMs) == 0 {
		return fmt.Errorf("no VMs specified (use --name, --all, --all-disabled)")
	}

	// Enable guest-exec for each VM
	logger.Info("Enabling guest-exec for VMs", zap.Int("vm_count", len(targetVMs)))

	for _, vmName := range targetVMs {
		logger.Info("Enabling guest-exec", zap.String("vm", vmName))
		if err := kvm.EnableGuestExec(rc, vmName); err != nil {
			logger.Error("Failed to enable guest-exec",
				zap.String("vm", vmName),
				zap.Error(err))
			return err
		}
	}

	logger.Info("Successfully enabled guest-exec for all VMs")
	return nil
}

// runRestartOperation handles --restart operations (orchestration only)
func runRestartOperation(rc *eos_io.RuntimeContext) error {
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

		if !kvmRolling && !(kvmYes || kvmForce) {
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

	// Get target VMs
	targetVMs, err := getTargetVMs(rc, false, false)
	if err != nil {
		return err
	}

	if len(targetVMs) == 0 {
		return fmt.Errorf("no VMs specified (use --name, --all, --all-drift)")
	}

	// Handle multiple VMs
	if len(targetVMs) > 1 {
		logger.Info("Restarting multiple VMs",
			zap.Int("count", len(targetVMs)),
			zap.Bool("rolling", kvmRolling))

		if !kvmRolling && !(kvmYes || kvmForce) {
			fmt.Printf("⚠ WARNING: Restarting %d VMs simultaneously!\n", len(targetVMs))
			fmt.Print("Continue? (yes/no): ")
			var response string
			_, _ = fmt.Scanln(&response)
			if response != "yes" && response != "y" {
				fmt.Println("Cancelled")
				return nil
			}
		}

		waitBetween := time.Duration(kvmWaitBetween) * time.Second
		return kvm.RestartMultipleVMs(rc.Ctx, targetVMs, cfg, kvmRolling, kvmBatchSize, waitBetween)
	}

	// Single VM restart
	vmName := targetVMs[0]
	logger.Info("Restarting VM", zap.String("vm", vmName))

	if !cfg.CreateSnapshot && !cfg.SkipSafetyChecks {
		fmt.Println("ℹ Tip: Use --snapshot to create a safety snapshot before restart")
	}

	if err := kvm.RestartVM(rc.Ctx, vmName, cfg); err != nil {
		logger.Error("Failed to restart VM", zap.String("vm", vmName), zap.Error(err))
		return err
	}

	fmt.Printf("✓ VM %s restarted successfully\n", vmName)
	return nil
}

// runRescueMode opens virt-rescue shell (legacy behavior)
func runRescueMode(rc *eos_io.RuntimeContext, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(args) == 0 {
		return fmt.Errorf("rescue mode requires VM name, or use --add/--enable/--restart flags")
	}

	vmName := args[0]
	logger.Info("🛠 Starting rescue for KVM VM", zap.String("vm", vmName))

	// Check VM status
	state, err := kvm.GetDomainState(rc.Ctx, vmName)
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	if state == "shutoff" {
		logger.Info("✓ VM is already shut off", zap.String("vm", vmName))
	} else {
		logger.Info("Shutting down VM...", zap.String("vm", vmName))
		if err := kvm.ShutdownDomain(rc.Ctx, vmName); err != nil {
			return fmt.Errorf("failed to shutdown VM: %w", err)
		}

		logger.Info("⏳ Waiting for VM to shut off...")
		for i := 0; i < 100; i++ {
			time.Sleep(3 * time.Second)
			state, err := kvm.GetDomainState(rc.Ctx, vmName)
			if err != nil {
				return fmt.Errorf("failed to get VM state: %w", err)
			}
			if state == "shutoff" {
				logger.Info("✓ VM is now shut off", zap.String("vm", vmName))
				break
			}
			logger.Debug("...still waiting for VM to shut off")
		}
	}

	// Launch virt-rescue
	logger.Info("🚀 Launching virt-rescue shell (requires sudo)", zap.String("vm", vmName))
	cmdRescue := exec.Command("sudo", "virt-rescue", "-d", vmName)
	cmdRescue.Stdout = os.Stdout
	cmdRescue.Stderr = os.Stderr
	cmdRescue.Stdin = os.Stdin
	if err := cmdRescue.Run(); err != nil {
		return fmt.Errorf("virt-rescue failed: %w", err)
	}

	logger.Info("✓ Rescue session completed")
	return nil
}

// getTargetVMs returns list of VMs based on selection flags
func getTargetVMs(rc *eos_io.RuntimeContext, onlyDisabled bool, onlyDrift bool) ([]string, error) {
	// If specific names provided, use those
	if len(kvmName) > 0 {
		return kvmName, nil
	}

	// If --all flag
	if kvmAll {
		return kvm.ListAllVMNames(rc.Ctx)
	}

	// If --all-disabled flag
	if kvmAllDisabled && onlyDisabled {
		// This is handled specially in runEnableOperation
		return nil, nil
	}

	return nil, nil
}

// showImpactAndConfirm shows impact summary and gets user confirmation
func showImpactAndConfirm(rc *eos_io.RuntimeContext, vmsNeedingUpdate []string) bool {
	logger := otelzap.Ctx(rc.Ctx)

	runningCount := 0
	for _, vmName := range vmsNeedingUpdate {
		if kvm.IsVMRunning(rc.Ctx, vmName) {
			runningCount++
		}
	}

	logger.Info("╔═══════════════════════════════════════════════════════════════╗")
	logger.Info("║                    OPERATION SUMMARY                          ║")
	logger.Info("╠═══════════════════════════════════════════════════════════════╣")
	logger.Info(fmt.Sprintf("║ Operation: Add QEMU Guest Agent Channel                       ║"))
	logger.Info(fmt.Sprintf("║ Total VMs to update: %-41d║", len(vmsNeedingUpdate)))
	logger.Info(fmt.Sprintf("║ Running VMs (may need restart): %-26d║", runningCount))
	logger.Info(fmt.Sprintf("║ Batch size: %-50d║", kvmBatchSize))
	logger.Info(fmt.Sprintf("║ Wait between batches: %-39ds║", kvmWaitBetween))
	logger.Info("╚═══════════════════════════════════════════════════════════════╝")
	logger.Info("")
	logger.Info("This operation will:")
	logger.Info("  ✓ Modify VM XML configurations")
	logger.Info("  ✓ Add virtio-serial controller (if missing)")
	logger.Info("  ✓ Add guest agent channel device")
	logger.Info("  ✓ Create backups before modification")
	logger.Info("")
	logger.Info("terminal prompt: Type 'yes' to continue")

	var response string
	fmt.Print("Do you want to proceed? (yes/no): ")
	_, _ = fmt.Scanln(&response)

	return strings.ToLower(response) == "yes"
}

func init() {
	// Action flags
	updateKvmCmd.Flags().BoolVar(&kvmAdd, "add", false, "Add features/configuration to VMs")
	updateKvmCmd.Flags().BoolVar(&kvmEnable, "enable", false, "Enable features on VMs")
	updateKvmCmd.Flags().BoolVar(&kvmRestart, "restart", false, "Restart VMs")

	// Target flags
	updateKvmCmd.Flags().BoolVar(&kvmGuestAgent, "guest-agent", false, "Target: QEMU guest agent")
	updateKvmCmd.Flags().BoolVar(&kvmGuestExec, "guest-exec", false, "Target: Guest-exec capability")

	// Selection flags
	updateKvmCmd.Flags().StringSliceVar(&kvmName, "name", []string{}, "VM name (can be repeated)")
	updateKvmCmd.Flags().BoolVar(&kvmAll, "all", false, "All VMs")
	updateKvmCmd.Flags().BoolVar(&kvmAllDisabled, "all-disabled", false, "All VMs with guest-exec disabled")
	updateKvmCmd.Flags().BoolVar(&kvmAllDrift, "all-drift", false, "All VMs with QEMU drift")

	// Modifier flags
	updateKvmCmd.Flags().BoolVar(&kvmDryRun, "dry-run", false, "Preview changes without applying")
	updateKvmCmd.Flags().BoolVar(&kvmYes, "yes", false, "Skip confirmation prompts")
	updateKvmCmd.Flags().BoolVar(&kvmForce, "force", false, "Force operation (alias for --yes)")
	updateKvmCmd.Flags().IntVar(&kvmBatchSize, "batch-size", 3, "VMs to process in each batch")
	updateKvmCmd.Flags().IntVar(&kvmWaitBetween, "wait-between", 30, "Seconds between batches")
	updateKvmCmd.Flags().BoolVar(&kvmNoBackup, "no-backup", false, "Skip XML backups")
	updateKvmCmd.Flags().BoolVar(&kvmNoRestart, "no-restart", false, "Skip restart prompts")

	// Restart-specific flags
	updateKvmCmd.Flags().BoolVar(&kvmNoSafe, "no-safe", false, "Skip safety checks")
	updateKvmCmd.Flags().BoolVar(&kvmSnapshot, "snapshot", false, "Create snapshot before restart")
	updateKvmCmd.Flags().StringVar(&kvmSnapshotName, "snapshot-name", "", "Custom snapshot name")
	updateKvmCmd.Flags().IntVar(&kvmTimeout, "timeout", 300, "Shutdown timeout in seconds")
	updateKvmCmd.Flags().BoolVar(&kvmRolling, "rolling", false, "Rolling restart mode")

	UpdateCmd.AddCommand(updateKvmCmd)
}
