//go:build linux

// pkg/kvm/update_operations.go
// Business logic for KVM update operations (add, enable, restart, rescue)

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AddOperationConfig configures the add operation
type AddOperationConfig struct {
	TargetVMs   []string
	DryRun      bool
	Force       bool
	BatchSize   int
	WaitBetween int
	NoBackup    bool
	NoRestart   bool
}

// EnableOperationConfig configures the enable operation
type EnableOperationConfig struct {
	TargetVMs   []string
	AllDisabled bool
	Force       bool
}

// RestartOperationConfig configures the restart operation
type RestartOperationConfig struct {
	TargetVMs     []string
	AllDrift      bool
	Rolling       bool
	BatchSize     int
	WaitBetween   time.Duration
	RestartConfig *RestartConfig
	Force         bool
}

// RunAddGuestAgentOperation orchestrates adding guest agent channel to VMs
func RunAddGuestAgentOperation(rc *eos_io.RuntimeContext, config *AddOperationConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(config.TargetVMs) == 0 {
		return fmt.Errorf("no VMs specified for add operation")
	}

	logger.Info("Adding guest agent channel to VMs",
		zap.Int("vm_count", len(config.TargetVMs)),
		zap.Bool("dry_run", config.DryRun))

	// Build configuration for AddGuestAgentToVMs
	addConfig := &GuestAgentAddConfig{
		VMNames:     config.TargetVMs,
		DryRun:      config.DryRun,
		Force:       config.Force,
		BatchSize:   config.BatchSize,
		WaitBetween: config.WaitBetween,
		NoBackup:    config.NoBackup,
		NoRestart:   config.NoRestart,
	}

	// Call business logic
	result, err := AddGuestAgentToVMs(rc, addConfig)
	if err != nil {
		return err
	}

	// Handle restart prompts for running VMs
	if !config.NoRestart && !config.DryRun && len(result.UpdatedVMs) > 0 {
		for _, vmName := range result.UpdatedVMs {
			if IsVMRunning(rc.Ctx, vmName) {
				if shouldRestart := PromptVMRestart(rc, vmName); shouldRestart {
					logger.Info("Restarting VM", zap.String("vm", vmName))
					if err := RestartVM(rc.Ctx, vmName, DefaultRestartConfig()); err != nil {
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

// RunEnableGuestExecOperation orchestrates enabling guest-exec for VMs
func RunEnableGuestExecOperation(rc *eos_io.RuntimeContext, config *EnableOperationConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Handle bulk operation for all-disabled
	if config.AllDisabled {
		logger.Info("Enabling guest-exec for all VMs with DISABLED status")
		return EnableGuestExecBulk(rc, config.Force)
	}

	if len(config.TargetVMs) == 0 {
		return fmt.Errorf("no VMs specified for enable operation")
	}

	// Enable guest-exec for each VM
	logger.Info("Enabling guest-exec for VMs", zap.Int("vm_count", len(config.TargetVMs)))

	for _, vmName := range config.TargetVMs {
		logger.Info("Enabling guest-exec", zap.String("vm", vmName))
		if err := EnableGuestExec(rc, vmName); err != nil {
			logger.Error("Failed to enable guest-exec",
				zap.String("vm", vmName),
				zap.Error(err))
			return err
		}
	}

	logger.Info("Successfully enabled guest-exec for all VMs")
	return nil
}

// RunRestartVMsOperation orchestrates VM restart operations
func RunRestartVMsOperation(rc *eos_io.RuntimeContext, config *RestartOperationConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	ctx := rc.Ctx

	// Handle --all-drift flag
	if config.AllDrift {
		logger.Info("Restarting all VMs with QEMU drift",
			zap.Bool("rolling", config.Rolling),
			zap.Int("batch_size", config.BatchSize))

		if !config.Rolling && !config.Force {
			logger.Warn("WARNING: Restarting all VMs with drift simultaneously may cause service disruption!")
			if !PromptConfirmation(rc, "Continue?") {
				return nil
			}
		}

		return RestartVMsWithDrift(ctx, config.RestartConfig, config.Rolling, config.BatchSize, config.WaitBetween)
	}

	if len(config.TargetVMs) == 0 {
		return fmt.Errorf("no VMs specified for restart operation")
	}

	// Handle multiple VMs
	if len(config.TargetVMs) > 1 {
		logger.Info("Restarting multiple VMs",
			zap.Int("count", len(config.TargetVMs)),
			zap.Bool("rolling", config.Rolling))

		if !config.Rolling && !config.Force {
			logger.Warn("WARNING: Restarting multiple VMs simultaneously!")
			if !PromptConfirmation(rc, fmt.Sprintf("Restart %d VMs?", len(config.TargetVMs))) {
				return nil
			}
		}

		return RestartMultipleVMs(ctx, config.TargetVMs, config.RestartConfig, config.Rolling, config.BatchSize, config.WaitBetween)
	}

	// Single VM restart
	vmName := config.TargetVMs[0]
	logger.Info("Restarting VM", zap.String("vm", vmName))

	if !config.RestartConfig.CreateSnapshot && !config.RestartConfig.SkipSafetyChecks {
		logger.Info("Tip: Use --snapshot to create a safety snapshot before restart")
	}

	if err := RestartVM(ctx, vmName, config.RestartConfig); err != nil {
		logger.Error("Failed to restart VM", zap.String("vm", vmName), zap.Error(err))
		return err
	}

	logger.Info("VM restarted successfully", zap.String("vm", vmName))
	return nil
}

// RunRescueModeOperation orchestrates virt-rescue shell for a VM
func RunRescueModeOperation(rc *eos_io.RuntimeContext, vmName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting rescue for KVM VM", zap.String("vm", vmName))

	// Check VM status
	state, err := GetDomainState(rc.Ctx, vmName)
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	if state == "shutoff" {
		logger.Info("VM is already shut off", zap.String("vm", vmName))
	} else {
		logger.Info("Shutting down VM...", zap.String("vm", vmName))
		if err := ShutdownDomain(rc.Ctx, vmName); err != nil {
			return fmt.Errorf("failed to shutdown VM: %w", err)
		}

		logger.Info("Waiting for VM to shut off...")
		for i := 0; i < 100; i++ {
			time.Sleep(3 * time.Second)
			state, err := GetDomainState(rc.Ctx, vmName)
			if err != nil {
				return fmt.Errorf("failed to get VM state: %w", err)
			}
			if state == "shutoff" {
				logger.Info("VM is now shut off", zap.String("vm", vmName))
				break
			}
			logger.Debug("...still waiting for VM to shut off")
		}
	}

	// Launch virt-rescue
	logger.Info("Launching virt-rescue shell (requires sudo)", zap.String("vm", vmName))
	cmdRescue := exec.Command("sudo", "virt-rescue", "-d", vmName)
	cmdRescue.Stdout = os.Stdout
	cmdRescue.Stderr = os.Stderr
	cmdRescue.Stdin = os.Stdin
	if err := cmdRescue.Run(); err != nil {
		return fmt.Errorf("virt-rescue failed: %w", err)
	}

	logger.Info("Rescue session completed")
	return nil
}

// PromptVMRestart prompts user if they want to restart a VM
func PromptVMRestart(rc *eos_io.RuntimeContext, vmName string) bool {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("")
	logger.Info("VM is running - restart required for guest agent channel to be available",
		zap.String("vm", vmName))
	logger.Info("terminal prompt: Restart VM now?")

	var response string
	fmt.Printf("Restart %s now? (yes/no): ", vmName)
	_, _ = fmt.Scanln(&response)

	return strings.ToLower(response) == "yes"
}

// PromptConfirmation prompts user for yes/no confirmation
func PromptConfirmation(rc *eos_io.RuntimeContext, message string) bool {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("terminal prompt: " + message)

	var response string
	fmt.Printf("%s (yes/no): ", message)
	_, _ = fmt.Scanln(&response)

	return response == "yes" || response == "y"
}

// ShowImpactSummary displays a summary of the operation's impact
func ShowImpactSummary(rc *eos_io.RuntimeContext, vmsNeedingUpdate []string, batchSize, waitBetween int) {
	logger := otelzap.Ctx(rc.Ctx)

	runningCount := 0
	for _, vmName := range vmsNeedingUpdate {
		if IsVMRunning(rc.Ctx, vmName) {
			runningCount++
		}
	}

	logger.Info("╔═══════════════════════════════════════════════════════════════╗")
	logger.Info("║                    OPERATION SUMMARY                          ║")
	logger.Info("╠═══════════════════════════════════════════════════════════════╣")
	logger.Info("║ Operation: Add QEMU Guest Agent Channel                       ║")
	logger.Info(fmt.Sprintf("║ Total VMs to update: %-41d║", len(vmsNeedingUpdate)))
	logger.Info(fmt.Sprintf("║ Running VMs (may need restart): %-26d║", runningCount))
	logger.Info(fmt.Sprintf("║ Batch size: %-50d║", batchSize))
	logger.Info(fmt.Sprintf("║ Wait between batches: %-39ds║", waitBetween))
	logger.Info("╚═══════════════════════════════════════════════════════════════╝")
	logger.Info("")
	logger.Info("This operation will:")
	logger.Info("  ✓ Modify VM XML configurations")
	logger.Info("  ✓ Add virtio-serial controller (if missing)")
	logger.Info("  ✓ Add guest agent channel device")
	logger.Info("  ✓ Create backups before modification")
	logger.Info("")
}
