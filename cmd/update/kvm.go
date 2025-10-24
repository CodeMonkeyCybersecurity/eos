//go:build linux

// cmd/update/kvm.go
// Orchestration layer for KVM update operations

package update

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
			if len(args) == 0 {
				return fmt.Errorf("rescue mode requires VM name, or use --add/--enable/--restart flags")
			}
			return kvm.RunRescueModeOperation(rc, args[0])
		}

		// Validate: only one action at a time
		if actionCount > 1 {
			return fmt.Errorf("only one action flag allowed at a time: --add, --enable, or --restart")
		}

		// Route to appropriate handler
		if kvmAdd {
			return handleAddOperation(rc)
		}
		if kvmEnable {
			return handleEnableOperation(rc)
		}
		if kvmRestart {
			return handleRestartOperation(rc)
		}

		return fmt.Errorf("no valid operation specified")
	}),
}

// handleAddOperation processes --add flag operations
func handleAddOperation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate target
	if !kvmGuestAgent {
		return fmt.Errorf("--add requires a target: --guest-agent")
	}

	// Get target VMs
	targetVMs, err := getTargetVMs(rc)
	if err != nil {
		return err
	}

	if len(targetVMs) == 0 {
		return fmt.Errorf("no VMs specified (use --name, --all, or provide VM names)")
	}

	// Show impact and get confirmation (unless --yes or --force)
	if (!kvmYes && !kvmForce) && !kvmDryRun {
		kvm.ShowImpactSummary(rc, targetVMs, kvmBatchSize, kvmWaitBetween)
		logger.Info("terminal prompt: Type 'yes' to continue")
		if !kvm.PromptConfirmation(rc, "Do you want to proceed?") {
			logger.Info("Operation cancelled by user")
			return nil
		}
	}

	// Build configuration and call pkg
	config := &kvm.AddOperationConfig{
		TargetVMs:   targetVMs,
		DryRun:      kvmDryRun,
		Force:       kvmYes || kvmForce,
		BatchSize:   kvmBatchSize,
		WaitBetween: kvmWaitBetween,
		NoBackup:    kvmNoBackup,
		NoRestart:   kvmNoRestart,
	}

	return kvm.RunAddGuestAgentOperation(rc, config)
}

// handleEnableOperation processes --enable flag operations
func handleEnableOperation(rc *eos_io.RuntimeContext) error {
	// Validate target
	if !kvmGuestExec && !kvmGuestAgent {
		return fmt.Errorf("--enable requires a target: --guest-exec or --guest-agent")
	}

	// --guest-agent with --enable is same as --guest-exec
	if kvmGuestAgent {
		kvmGuestExec = true
	}

	// Get target VMs (unless using --all-disabled)
	var targetVMs []string
	var err error
	if !kvmAllDisabled {
		targetVMs, err = getTargetVMs(rc)
		if err != nil {
			return err
		}

		if len(targetVMs) == 0 {
			return fmt.Errorf("no VMs specified (use --name, --all, --all-disabled)")
		}
	}

	// Build configuration and call pkg
	config := &kvm.EnableOperationConfig{
		TargetVMs:   targetVMs,
		AllDisabled: kvmAllDisabled,
		Force:       kvmYes || kvmForce,
	}

	return kvm.RunEnableGuestExecOperation(rc, config)
}

// handleRestartOperation processes --restart flag operations
func handleRestartOperation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get target VMs (unless using --all-drift)
	var targetVMs []string
	var err error
	if !kvmAllDrift {
		targetVMs, err = getTargetVMs(rc)
		if err != nil {
			return err
		}

		if len(targetVMs) == 0 {
			return fmt.Errorf("no VMs specified (use --name, --all, --all-drift)")
		}
	}

	// Build restart configuration
	restartCfg := kvm.DefaultRestartConfig()
	restartCfg.SkipSafetyChecks = kvmNoSafe
	restartCfg.CreateSnapshot = kvmSnapshot
	restartCfg.ShutdownTimeout = time.Duration(kvmTimeout) * time.Second

	if kvmSnapshotName != "" {
		restartCfg.SnapshotName = kvmSnapshotName
	}

	logger.Info("KVM restart configuration",
		zap.Bool("safe_mode", !restartCfg.SkipSafetyChecks),
		zap.Bool("snapshot", restartCfg.CreateSnapshot),
		zap.Duration("timeout", restartCfg.ShutdownTimeout))

	// Build operation configuration and call pkg
	config := &kvm.RestartOperationConfig{
		TargetVMs:     targetVMs,
		AllDrift:      kvmAllDrift,
		Rolling:       kvmRolling,
		BatchSize:     kvmBatchSize,
		WaitBetween:   time.Duration(kvmWaitBetween) * time.Second,
		RestartConfig: restartCfg,
		Force:         kvmYes || kvmForce,
	}

	return kvm.RunRestartVMsOperation(rc, config)
}

// getTargetVMs returns list of VMs based on selection flags
func getTargetVMs(rc *eos_io.RuntimeContext) ([]string, error) {
	// If specific names provided, use those
	if len(kvmName) > 0 {
		return kvmName, nil
	}

	// If --all flag
	if kvmAll {
		return kvm.ListAllVMNames(rc.Ctx)
	}

	return nil, nil
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
