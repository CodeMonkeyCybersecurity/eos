//go:build linux

// pkg/kvm/upgrade_and_reboot.go
// Orchestrates package upgrade + VM reboot cycle to resolve QEMU drift

package kvm

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpgradeAndRebootConfig configures the full upgrade cycle
type UpgradeAndRebootConfig struct {
	// Package upgrade settings
	PackageConfig *PackageUpgradeConfig

	// Restart settings
	RestartConfig *RestartConfig

	// Safety settings
	CreateSnapshot   bool   // Create snapshot before upgrade (default: true)
	SnapshotName     string // Custom snapshot name (optional)
	DeleteSnapshot   bool   // Delete snapshot after success (default: false)
	KeepSnapshotDays int    // Days to keep snapshot (default: 7)

	// Operation control
	DryRun      bool // Show what would be done (default: false)
	SkipUpgrade bool // Just reboot, skip package upgrade
	SkipReboot  bool // Just upgrade, skip reboot

	// Batch processing
	ContinueOnError bool // Continue with other VMs if one fails
}

// DefaultUpgradeAndRebootConfig returns sensible defaults
func DefaultUpgradeAndRebootConfig() *UpgradeAndRebootConfig {
	return &UpgradeAndRebootConfig{
		PackageConfig:    DefaultPackageUpgradeConfig(),
		RestartConfig:    DefaultRestartConfig(),
		CreateSnapshot:   true,
		KeepSnapshotDays: 7,
		DryRun:           false,
		SkipUpgrade:      false,
		SkipReboot:       false,
		ContinueOnError:  false,
	}
}

// UpgradeAndRebootResult contains results of the full operation
type UpgradeAndRebootResult struct {
	Success         bool                  `json:"success"`
	VMName          string                `json:"vm_name"`
	SnapshotCreated bool                  `json:"snapshot_created"`
	SnapshotName    string                `json:"snapshot_name,omitempty"`
	PackageResult   *PackageUpgradeResult `json:"package_result,omitempty"`
	RestartedVM     bool                  `json:"restarted_vm"`
	DriftResolved   bool                  `json:"drift_resolved"`
	Duration        time.Duration         `json:"duration"`
	ErrorMessage    string                `json:"error_message,omitempty"`
}

// UpgradeAndRebootVM performs the complete upgrade cycle for a single VM
// Follows Assess → Intervene → Evaluate pattern at the orchestration level
func UpgradeAndRebootVM(rc *eos_io.RuntimeContext, vmName string, cfg *UpgradeAndRebootConfig) (*UpgradeAndRebootResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	if cfg == nil {
		cfg = DefaultUpgradeAndRebootConfig()
	}

	logger.Info("Starting upgrade and reboot cycle",
		zap.String("vm", vmName),
		zap.Bool("dry_run", cfg.DryRun),
		zap.Bool("create_snapshot", cfg.CreateSnapshot),
		zap.Bool("skip_upgrade", cfg.SkipUpgrade),
		zap.Bool("skip_reboot", cfg.SkipReboot))

	result := &UpgradeAndRebootResult{
		VMName: vmName,
	}

	// ASSESS: Pre-flight checks
	if err := assessUpgradeAndReboot(rc, vmName, cfg); err != nil {
		result.ErrorMessage = fmt.Sprintf("Pre-flight checks failed: %v", err)
		return result, err
	}

	// INTERVENE: Execute upgrade cycle
	if err := interveneUpgradeAndReboot(rc, vmName, cfg, result); err != nil {
		result.ErrorMessage = fmt.Sprintf("Upgrade cycle failed: %v", err)
		return result, err
	}

	// EVALUATE: Verify success
	if err := evaluateUpgradeAndReboot(rc, vmName, cfg, result); err != nil {
		result.ErrorMessage = fmt.Sprintf("Post-upgrade verification failed: %v", err)
		return result, err
	}

	result.Success = true
	result.Duration = time.Since(startTime)

	logger.Info("Upgrade and reboot cycle completed",
		zap.String("vm", vmName),
		zap.Bool("drift_resolved", result.DriftResolved),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// UpgradeAndRebootMultiple processes multiple VMs sequentially or in batches
func UpgradeAndRebootMultiple(rc *eos_io.RuntimeContext, vmNames []string, cfg *UpgradeAndRebootConfig, rolling bool, batchSize int, waitBetween time.Duration) ([]*UpgradeAndRebootResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting batch upgrade and reboot",
		zap.Int("total_vms", len(vmNames)),
		zap.Bool("rolling", rolling),
		zap.Int("batch_size", batchSize),
		zap.Duration("wait_between", waitBetween))

	results := make([]*UpgradeAndRebootResult, 0, len(vmNames))

	if !rolling {
		// Process all VMs (dangerous!)
		logger.Warn("Processing all VMs without rolling mode")
		for _, vmName := range vmNames {
			result, err := UpgradeAndRebootVM(rc, vmName, cfg)
			results = append(results, result)

			if err != nil && !cfg.ContinueOnError {
				return results, fmt.Errorf("failed on VM %s: %w", vmName, err)
			}
		}
		return results, nil
	}

	// Rolling upgrade with batches
	for i := 0; i < len(vmNames); i += batchSize {
		end := i + batchSize
		if end > len(vmNames) {
			end = len(vmNames)
		}

		batch := vmNames[i:end]
		logger.Info("Processing batch",
			zap.Int("batch", i/batchSize+1),
			zap.Strings("vms", batch))

		for _, vmName := range batch {
			result, err := UpgradeAndRebootVM(rc, vmName, cfg)
			results = append(results, result)

			if err != nil {
				logger.Error("Failed to upgrade VM in batch",
					zap.String("vm", vmName),
					zap.Error(err))

				if !cfg.ContinueOnError {
					return results, fmt.Errorf("failed on VM %s: %w", vmName, err)
				}
			}
		}

		// Wait between batches (except after last batch)
		if end < len(vmNames) {
			logger.Info("Waiting before next batch",
				zap.Duration("wait", waitBetween))
			time.Sleep(waitBetween)
		}
	}

	return results, nil
}

// UpgradeAndRebootVMsWithDrift upgrades all VMs that have QEMU drift
func UpgradeAndRebootVMsWithDrift(rc *eos_io.RuntimeContext, cfg *UpgradeAndRebootConfig, rolling bool, batchSize int, waitBetween time.Duration) ([]*UpgradeAndRebootResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get all VMs
	vms, err := ListVMs(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to list VMs: %w", err)
	}

	// Filter to only VMs with drift
	driftVMs := FilterVMsWithDrift(vms)

	if len(driftVMs) == 0 {
		logger.Info("No VMs with QEMU drift detected")
		return []*UpgradeAndRebootResult{}, nil
	}

	vmNames := make([]string, len(driftVMs))
	for i, vm := range driftVMs {
		vmNames[i] = vm.Name
	}

	logger.Info("Found VMs with QEMU drift",
		zap.Int("count", len(vmNames)),
		zap.Strings("vms", vmNames))

	return UpgradeAndRebootMultiple(rc, vmNames, cfg, rolling, batchSize, waitBetween)
}

// assessUpgradeAndReboot performs pre-flight checks
func assessUpgradeAndReboot(rc *eos_io.RuntimeContext, vmName string, cfg *UpgradeAndRebootConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Pre-flight checks for upgrade cycle",
		zap.String("vm", vmName))

	// Check VM exists and is running
	vms, err := ListVMs(rc)
	if err != nil {
		return fmt.Errorf("failed to list VMs: %w", err)
	}

	var targetVM *VMInfo
	for i := range vms {
		if vms[i].Name == vmName {
			targetVM = &vms[i]
			break
		}
	}

	if targetVM == nil {
		return fmt.Errorf("VM %s not found", vmName)
	}

	if targetVM.State != "running" {
		return fmt.Errorf("VM %s is not running (state: %s)", vmName, targetVM.State)
	}

	// Check guest agent is available
	if !targetVM.GuestAgentOK {
		return fmt.Errorf("guest agent not responsive on VM %s - ensure qemu-guest-agent is installed and running", vmName)
	}

	logger.Debug("Pre-flight checks passed",
		zap.String("vm", vmName),
		zap.String("state", targetVM.State))

	return nil
}

// interveneUpgradeAndReboot executes the upgrade cycle
func interveneUpgradeAndReboot(rc *eos_io.RuntimeContext, vmName string, cfg *UpgradeAndRebootConfig, result *UpgradeAndRebootResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Step 1: Create snapshot (if enabled and not dry-run)
	if cfg.CreateSnapshot && !cfg.DryRun {
		snapshotName := cfg.SnapshotName
		if snapshotName == "" {
			snapshotName = fmt.Sprintf("pre-upgrade-%s", time.Now().Format("20060102-150405"))
		}

		logger.Info("Creating snapshot before upgrade",
			zap.String("vm", vmName),
			zap.String("snapshot", snapshotName))

		snapshotCfg := &SnapshotConfig{
			VMName:       vmName,
			SnapshotName: snapshotName,
			Description:  "Automatic snapshot before package upgrade",
			LiveSnapshot: true,
		}

		snapshotMgr := NewSnapshotManager(snapshotCfg, otelzap.Ctx(rc.Ctx))
		_, err := snapshotMgr.CreateSnapshot(rc)
		if err != nil {
			return fmt.Errorf("failed to create snapshot: %w", err)
		}

		result.SnapshotCreated = true
		result.SnapshotName = snapshotName

		logger.Info("Snapshot created successfully",
			zap.String("snapshot", snapshotName))
	}

	// Step 2: Upgrade packages (unless --skip-upgrade)
	if !cfg.SkipUpgrade {
		logger.Info("Upgrading packages",
			zap.String("vm", vmName))

		packageResult, err := UpgradeVMPackages(rc, vmName, cfg.PackageConfig)
		result.PackageResult = packageResult

		if err != nil {
			// Upgrade failed - attempt rollback if snapshot exists
			if result.SnapshotCreated && !cfg.DryRun {
				logger.Error("Package upgrade failed, snapshot available for manual rollback",
					zap.String("vm", vmName),
					zap.String("snapshot", result.SnapshotName),
					zap.Error(err))
			}
			return fmt.Errorf("package upgrade failed: %w", err)
		}

		logger.Info("Package upgrade completed",
			zap.String("vm", vmName),
			zap.Int("packages_upgraded", packageResult.PackagesUpgraded))
	}

	// Step 3: Reboot VM (unless --skip-reboot or dry-run)
	if !cfg.SkipReboot && !cfg.DryRun {
		logger.Info("Rebooting VM",
			zap.String("vm", vmName))

		if err := RestartVM(rc.Ctx, vmName, cfg.RestartConfig); err != nil {
			return fmt.Errorf("VM restart failed: %w", err)
		}

		result.RestartedVM = true

		logger.Info("VM restarted successfully",
			zap.String("vm", vmName))
	}

	return nil
}

// evaluateUpgradeAndReboot verifies the upgrade was successful
func evaluateUpgradeAndReboot(rc *eos_io.RuntimeContext, vmName string, cfg *UpgradeAndRebootConfig, result *UpgradeAndRebootResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	if cfg.DryRun {
		logger.Info("Dry-run mode - skipping verification")
		return nil
	}

	logger.Debug("Verifying upgrade cycle",
		zap.String("vm", vmName))

	// Check QEMU drift resolved (if VM was restarted)
	if result.RestartedVM {
		vms, err := ListVMs(rc)
		if err != nil {
			logger.Warn("Failed to verify drift resolution", zap.Error(err))
			return nil // Don't fail - verification error
		}

		for _, vm := range vms {
			if vm.Name == vmName {
				result.DriftResolved = !vm.DriftDetected

				if result.DriftResolved {
					logger.Info("QEMU drift resolved",
						zap.String("vm", vmName),
						zap.String("version", vm.QEMUVersion))
				} else {
					logger.Warn("QEMU drift still present",
						zap.String("vm", vmName),
						zap.String("vm_version", vm.QEMUVersion),
						zap.String("host_version", vm.HostQEMUVersion))
				}
				break
			}
		}
	}

	// Clean up snapshot if configured
	if result.SnapshotCreated && cfg.DeleteSnapshot {
		logger.Info("Deleting snapshot after successful upgrade",
			zap.String("snapshot", result.SnapshotName))

		snapshotCfg := &SnapshotConfig{
			VMName:       vmName,
			SnapshotName: result.SnapshotName,
		}
		snapshotMgr := NewSnapshotManager(snapshotCfg, otelzap.Ctx(rc.Ctx))

		if err := snapshotMgr.DeleteSnapshot(rc, result.SnapshotName, false); err != nil {
			logger.Warn("Failed to delete snapshot", zap.Error(err))
			// Don't fail - just a cleanup issue
		}
	}

	logger.Debug("Verification completed",
		zap.String("vm", vmName),
		zap.Bool("drift_resolved", result.DriftResolved))

	return nil
}
