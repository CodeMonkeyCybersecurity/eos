// pkg/kvm/restart.go
// Safe VM restart operations with health checks

package kvm

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

// RestartConfig contains configuration for VM restart operations
type RestartConfig struct {
	CreateSnapshot   bool
	SnapshotName     string
	ShutdownTimeout  time.Duration
	SkipSafetyChecks bool
	WaitForBoot      bool
	BootTimeout      time.Duration
}

// DefaultRestartConfig returns a safe default configuration
func DefaultRestartConfig() *RestartConfig {
	return &RestartConfig{
		CreateSnapshot:   false, // Opt-in for safety
		SnapshotName:     fmt.Sprintf("pre-restart-%d", time.Now().Unix()),
		ShutdownTimeout:  5 * time.Minute,
		SkipSafetyChecks: false,
		WaitForBoot:      true,
		BootTimeout:      5 * time.Minute,
	}
}

// RestartVM safely restarts a VM with health checks
func RestartVM(ctx context.Context, vmName string, cfg *RestartConfig) error {
	logger := otelzap.Ctx(ctx)

	if cfg == nil {
		cfg = DefaultRestartConfig()
	}

	logger.Info("Starting VM restart",
		zap.String("vm", vmName),
		zap.Bool("safe_mode", !cfg.SkipSafetyChecks),
		zap.Bool("snapshot", cfg.CreateSnapshot))

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer conn.Close()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("VM not found: %w", err)
	}
	defer domain.Free()

	// ASSESS - Pre-flight checks
	if !cfg.SkipSafetyChecks {
		logger.Info("Running safety checks", zap.String("vm", vmName))
		if err := assessVMRestart(ctx, domain); err != nil {
			return fmt.Errorf("safety check failed: %w", err)
		}
	}

	// INTERVENE - Perform restart
	if cfg.CreateSnapshot {
		logger.Info("Creating snapshot before restart", zap.String("snapshot", cfg.SnapshotName))
		if err := createRestartSnapshot(domain, cfg.SnapshotName); err != nil {
			return fmt.Errorf("failed to create snapshot: %w", err)
		}
	}

	logger.Info("Shutting down VM gracefully", zap.String("vm", vmName))
	if err := gracefulShutdown(ctx, domain, cfg.ShutdownTimeout); err != nil {
		return fmt.Errorf("shutdown failed: %w", err)
	}

	logger.Info("Starting VM", zap.String("vm", vmName))
	if err := domain.Create(); err != nil {
		// Attempt rollback if we created a snapshot
		if cfg.CreateSnapshot {
			logger.Error("Start failed, attempting rollback", zap.Error(err))
			rollbackErr := rollbackToSnapshot(domain, cfg.SnapshotName)
			if rollbackErr != nil {
				return fmt.Errorf("start failed and rollback also failed: %w (rollback error: %v)", err, rollbackErr)
			}
			return fmt.Errorf("start failed, rolled back to snapshot: %w", err)
		}
		return fmt.Errorf("failed to start VM: %w", err)
	}

	// EVALUATE - Post-restart validation
	if cfg.WaitForBoot {
		logger.Info("Waiting for VM to boot", zap.String("vm", vmName))
		if err := waitForBoot(ctx, domain, cfg.BootTimeout); err != nil {
			logger.Warn("Boot validation failed", zap.Error(err))
			// Don't fail the operation, just warn
		}
	}

	logger.Info("Validating VM restart", zap.String("vm", vmName))
	if err := validateVMRestart(ctx, domain); err != nil {
		logger.Warn("Post-restart validation warnings", zap.Error(err))
		// Don't fail, just warn
	}

	logger.Info("VM restarted successfully", zap.String("vm", vmName))
	return nil
}

// RestartMultipleVMs restarts multiple VMs with optional rolling restart
func RestartMultipleVMs(ctx context.Context, vmNames []string, cfg *RestartConfig, rolling bool, batchSize int, waitBetween time.Duration) error {
	logger := otelzap.Ctx(ctx)

	if !rolling {
		// Restart all VMs in parallel (dangerous!)
		logger.Warn("Restarting all VMs in parallel - this may cause service disruption")
		for _, vmName := range vmNames {
			if err := RestartVM(ctx, vmName, cfg); err != nil {
				logger.Error("Failed to restart VM", zap.String("vm", vmName), zap.Error(err))
				// Continue with other VMs
			}
		}
		return nil
	}

	// Rolling restart with batches
	logger.Info("Starting rolling restart",
		zap.Int("total_vms", len(vmNames)),
		zap.Int("batch_size", batchSize),
		zap.Duration("wait_between", waitBetween))

	for i := 0; i < len(vmNames); i += batchSize {
		end := i + batchSize
		if end > len(vmNames) {
			end = len(vmNames)
		}

		batch := vmNames[i:end]
		logger.Info("Restarting batch",
			zap.Int("batch", i/batchSize+1),
			zap.Strings("vms", batch))

		for _, vmName := range batch {
			if err := RestartVM(ctx, vmName, cfg); err != nil {
				logger.Error("Failed to restart VM in batch", zap.String("vm", vmName), zap.Error(err))
				// Continue with other VMs in batch
			}
		}

		// Wait between batches (except after last batch)
		if end < len(vmNames) {
			logger.Info("Waiting before next batch", zap.Duration("wait", waitBetween))
			time.Sleep(waitBetween)
		}
	}

	logger.Info("Rolling restart completed")
	return nil
}

// RestartVMsWithDrift restarts all VMs that have QEMU version drift
func RestartVMsWithDrift(ctx context.Context, cfg *RestartConfig, rolling bool, batchSize int, waitBetween time.Duration) error {
	logger := otelzap.Ctx(ctx)

	// Get all VMs
	vms, err := ListVMs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list VMs: %w", err)
	}

	// Filter to only VMs with drift
	driftVMs := FilterVMsWithDrift(vms)

	if len(driftVMs) == 0 {
		logger.Info("No VMs with QEMU drift detected")
		return nil
	}

	vmNames := make([]string, len(driftVMs))
	for i, vm := range driftVMs {
		vmNames[i] = vm.Name
	}

	logger.Info("Found VMs with QEMU drift",
		zap.Int("count", len(vmNames)),
		zap.Strings("vms", vmNames))

	return RestartMultipleVMs(ctx, vmNames, cfg, rolling, batchSize, waitBetween)
}

// assessVMRestart performs pre-restart safety checks
func assessVMRestart(ctx context.Context, domain *libvirt.Domain) error {
	logger := otelzap.Ctx(ctx)

	// Check VM is running
	state, _, err := domain.GetState()
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	if state != libvirt.DOMAIN_RUNNING {
		return fmt.Errorf("VM is not running (state: %s)", stateToString(state))
	}

	// Check guest agent (warn only)
	if !checkGuestAgent(domain) {
		logger.Warn("Guest agent not responsive - some checks will be skipped")
	}

	// TODO: Check for active SSH sessions via guest agent
	// TODO: Identify critical services

	return nil
}

// gracefulShutdown performs a graceful ACPI shutdown with timeout
func gracefulShutdown(ctx context.Context, domain *libvirt.Domain, timeout time.Duration) error {
	logger := otelzap.Ctx(ctx)

	// Send ACPI shutdown signal
	if err := domain.ShutdownFlags(libvirt.DOMAIN_SHUTDOWN_ACPI_POWER_BTN); err != nil {
		return fmt.Errorf("failed to send shutdown signal: %w", err)
	}

	logger.Info("Shutdown signal sent, waiting for VM to stop")

	// Wait for shutdown with timeout
	deadline := time.Now().Add(timeout)
	checkInterval := 2 * time.Second

	for time.Now().Before(deadline) {
		state, _, err := domain.GetState()
		if err != nil {
			return fmt.Errorf("failed to check VM state: %w", err)
		}

		if state == libvirt.DOMAIN_SHUTOFF {
			logger.Info("VM shut down gracefully")
			return nil
		}

		logger.Debug("Waiting for shutdown", zap.String("state", stateToString(state)))
		time.Sleep(checkInterval)
	}

	// Timeout exceeded - force shutdown
	logger.Warn("Graceful shutdown timeout exceeded, forcing shutdown")
	if err := domain.Destroy(); err != nil {
		return fmt.Errorf("failed to force shutdown: %w", err)
	}

	logger.Info("VM force-stopped")
	return nil
}

// waitForBoot waits for VM to fully boot and be responsive
func waitForBoot(ctx context.Context, domain *libvirt.Domain, timeout time.Duration) error {
	logger := otelzap.Ctx(ctx)

	deadline := time.Now().Add(timeout)
	checkInterval := 5 * time.Second

	for time.Now().Before(deadline) {
		// Check if VM is running
		state, _, err := domain.GetState()
		if err != nil {
			return fmt.Errorf("failed to check VM state: %w", err)
		}

		if state != libvirt.DOMAIN_RUNNING {
			logger.Debug("Waiting for VM to start running", zap.String("state", stateToString(state)))
			time.Sleep(checkInterval)
			continue
		}

		// Check if guest agent is responsive
		if checkGuestAgent(domain) {
			logger.Info("VM is running and guest agent is responsive")
			return nil
		}

		logger.Debug("VM running but guest agent not yet responsive")
		time.Sleep(checkInterval)
	}

	return fmt.Errorf("boot timeout exceeded (%s)", timeout)
}

// validateVMRestart performs post-restart validation
func validateVMRestart(ctx context.Context, domain *libvirt.Domain) error {
	logger := otelzap.Ctx(ctx)

	// Verify VM is running
	state, _, err := domain.GetState()
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	if state != libvirt.DOMAIN_RUNNING {
		return fmt.Errorf("VM is not running after restart (state: %s)", stateToString(state))
	}

	// Check QEMU version drift resolved
	hostVersion := getHostQEMUVersion()
	vmVersion := getVMQEMUVersion(domain)

	if vmVersion != "" && hostVersion != "" {
		if vmVersion == hostVersion {
			logger.Info("QEMU version drift resolved",
				zap.String("version", vmVersion))
		} else {
			logger.Warn("QEMU version drift still present",
				zap.String("vm_version", vmVersion),
				zap.String("host_version", hostVersion))
		}
	}

	// Check network connectivity
	ips := getVMIPs(domain)
	if len(ips) > 0 {
		logger.Info("VM network interfaces active", zap.Strings("ips", ips))
	} else {
		logger.Warn("No network IP addresses detected")
	}

	// Check guest agent
	if checkGuestAgent(domain) {
		logger.Info("Guest agent is responsive")
	} else {
		logger.Warn("Guest agent is not responsive")
	}

	return nil
}

// createRestartSnapshot creates a snapshot before restart
func createRestartSnapshot(domain *libvirt.Domain, snapshotName string) error {
	// XML for snapshot creation
	snapshotXML := fmt.Sprintf(`<domainsnapshot>
		<name>%s</name>
		<description>Automatic snapshot before restart</description>
	</domainsnapshot>`, snapshotName)

	_, err := domain.CreateSnapshotXML(snapshotXML, 0)
	return err
}

// rollbackToSnapshot reverts VM to a previous snapshot
func rollbackToSnapshot(domain *libvirt.Domain, snapshotName string) error {
	snapshot, err := domain.SnapshotLookupByName(snapshotName, 0)
	if err != nil {
		return fmt.Errorf("failed to find snapshot: %w", err)
	}
	defer snapshot.Free()

	return snapshot.RevertToSnapshot(0)
}
