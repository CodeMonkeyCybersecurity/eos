//go:build linux

// pkg/kvm/guest_agent_operations.go
// Business logic for QEMU guest agent channel management

package kvm

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

// GuestAgentAddConfig contains configuration for adding guest agent channels
type GuestAgentAddConfig struct {
	VMNames     []string
	DryRun      bool
	Force       bool
	BatchSize   int
	WaitBetween int
	NoBackup    bool
	NoRestart   bool
}

// GuestAgentAddResult contains results of guest agent addition
type GuestAgentAddResult struct {
	SuccessCount int
	FailedVMs    []string
	UpdatedVMs   []string
	SkippedVMs   []string
}

// AddGuestAgentToVMs adds guest agent channel to multiple VMs
func AddGuestAgentToVMs(rc *eos_io.RuntimeContext, config *GuestAgentAddConfig) (*GuestAgentAddResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	result := &GuestAgentAddResult{
		FailedVMs:  []string{},
		UpdatedVMs: []string{},
		SkippedVMs: []string{},
	}

	// Assess which VMs need updates
	vmsNeedingUpdate, vmsWithAgent, err := AssessVMsForGuestAgent(rc.Ctx, config.VMNames)
	if err != nil {
		return nil, fmt.Errorf("failed to assess VMs: %w", err)
	}

	if len(vmsWithAgent) > 0 {
		logger.Info("VMs already have guest agent channel", zap.Strings("vms", vmsWithAgent))
		result.SkippedVMs = vmsWithAgent
	}

	if len(vmsNeedingUpdate) == 0 {
		logger.Info("All specified VMs already have guest agent channel configured")
		return result, nil
	}

	logger.Info("VMs needing guest agent update",
		zap.Int("total", len(config.VMNames)),
		zap.Int("needs_update", len(vmsNeedingUpdate)),
		zap.Int("already_configured", len(vmsWithAgent)))

	// Dry run mode
	if config.DryRun {
		logger.Info("DRY RUN MODE - No changes will be made")
		for _, vmName := range vmsNeedingUpdate {
			logger.Info("Would add guest agent channel", zap.String("vm", vmName))
		}
		logger.Info("Dry run complete - no changes applied")
		result.UpdatedVMs = vmsNeedingUpdate
		return result, nil
	}

	// Apply updates
	if len(vmsNeedingUpdate) == 1 {
		err := updateSingleVMGuestAgent(rc, vmsNeedingUpdate[0], config)
		if err != nil {
			result.FailedVMs = append(result.FailedVMs, vmsNeedingUpdate[0])
			return result, err
		}
		result.UpdatedVMs = append(result.UpdatedVMs, vmsNeedingUpdate[0])
		result.SuccessCount = 1
		return result, nil
	}

	return updateMultipleVMsGuestAgent(rc, vmsNeedingUpdate, config)
}

// AssessVMsForGuestAgent checks which VMs need guest agent channel
func AssessVMsForGuestAgent(ctx context.Context, vmNames []string) (needsUpdate, hasAgent []string, err error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	for _, vmName := range vmNames {
		domain, err := conn.LookupDomainByName(vmName)
		if err != nil {
			continue
		}

		xmlDesc, err := domain.GetXMLDesc(0)
		_ = domain.Free()

		if err != nil {
			return nil, nil, fmt.Errorf("failed to get XML for %s: %w", vmName, err)
		}

		if strings.Contains(xmlDesc, "org.qemu.guest_agent.0") {
			hasAgent = append(hasAgent, vmName)
		} else {
			needsUpdate = append(needsUpdate, vmName)
		}
	}

	return needsUpdate, hasAgent, nil
}

// IsVMRunning checks if VM is currently running
func IsVMRunning(ctx context.Context, vmName string) bool {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return false
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return false
	}
	defer func() { _ = domain.Free() }()

	state, _, err := domain.GetState()
	if err != nil {
		return false
	}

	return state == libvirt.DOMAIN_RUNNING
}

// ListAllVMNames returns all VM names from libvirt
func ListAllVMNames(ctx context.Context) ([]string, error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domains, err := conn.ListAllDomains(0)
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	var vmNames []string
	for _, domain := range domains {
		name, err := domain.GetName()
		if err != nil {
			continue
		}
		vmNames = append(vmNames, name)
		domain.Free()
	}

	return vmNames, nil
}

// updateSingleVMGuestAgent updates a single VM
func updateSingleVMGuestAgent(rc *eos_io.RuntimeContext, vmName string, config *GuestAgentAddConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating single VM", zap.String("vm", vmName))

	wasRunning := IsVMRunning(rc.Ctx, vmName)
	if wasRunning {
		logger.Info("VM is currently running", zap.String("vm", vmName))
	}

	backupPath, err := addGuestAgentChannel(rc, vmName, config.NoBackup)
	if err != nil {
		return fmt.Errorf("failed to add guest agent to %s: %w", vmName, err)
	}

	logger.Info("Guest agent channel added successfully",
		zap.String("vm", vmName),
		zap.String("backup", backupPath))

	// Verify changes
	if err := verifyGuestAgentChannel(rc.Ctx, vmName); err != nil {
		logger.Error("Verification failed - rolling back", zap.Error(err))
		if restoreErr := restoreVMXML(rc, vmName, backupPath); restoreErr != nil {
			return fmt.Errorf("verification failed and rollback failed: %w, original error: %w", restoreErr, err)
		}
		return fmt.Errorf("verification failed, rolled back: %w", err)
	}

	// Prompt for restart if VM is running (handled by caller if NoRestart=true)
	logger.Info("Update complete", zap.String("vm", vmName))
	return nil
}

// updateMultipleVMsGuestAgent updates multiple VMs with batching
func updateMultipleVMsGuestAgent(rc *eos_io.RuntimeContext, vmNames []string, config *GuestAgentAddConfig) (*GuestAgentAddResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	result := &GuestAgentAddResult{
		FailedVMs:  []string{},
		UpdatedVMs: []string{},
		SkippedVMs: []string{},
	}

	batches := MakeBatches(vmNames, config.BatchSize)
	logger.Info("Progressive rollout plan",
		zap.Int("total_vms", len(vmNames)),
		zap.Int("batches", len(batches)),
		zap.Int("batch_size", config.BatchSize))

	for batchNum, batch := range batches {
		logger.Info(fmt.Sprintf("Processing batch %d/%d", batchNum+1, len(batches)),
			zap.Int("vms_in_batch", len(batch)))

		for _, vmName := range batch {
			logger.Info("Updating VM", zap.String("vm", vmName))

			backupPath, err := addGuestAgentChannel(rc, vmName, config.NoBackup)
			if err != nil {
				logger.Error("Failed to add guest agent", zap.String("vm", vmName), zap.Error(err))
				result.FailedVMs = append(result.FailedVMs, vmName)
				continue
			}

			if err := verifyGuestAgentChannel(rc.Ctx, vmName); err != nil {
				logger.Error("Verification failed - rolling back",
					zap.String("vm", vmName), zap.Error(err))

				if restoreErr := restoreVMXML(rc, vmName, backupPath); restoreErr != nil {
					logger.Error("Rollback also failed", zap.String("vm", vmName), zap.Error(restoreErr))
				} else {
					logger.Info("Rolled back successfully", zap.String("vm", vmName))
				}

				result.FailedVMs = append(result.FailedVMs, vmName)
				continue
			}

			result.SuccessCount++
			result.UpdatedVMs = append(result.UpdatedVMs, vmName)
			logger.Info("Successfully updated", zap.String("vm", vmName))
		}

		if batchNum < len(batches)-1 {
			logger.Info(fmt.Sprintf("Waiting %d seconds before next batch...", config.WaitBetween))
			time.Sleep(time.Duration(config.WaitBetween) * time.Second)
		}
	}

	logger.Info("Mass update complete",
		zap.Int("successful", result.SuccessCount),
		zap.Int("failed", len(result.FailedVMs)),
		zap.Int("total", len(vmNames)))

	if len(result.FailedVMs) > 0 {
		logger.Warn("Some VMs failed to update", zap.Strings("failed_vms", result.FailedVMs))
		return result, fmt.Errorf("%d VMs failed to update: %v", len(result.FailedVMs), result.FailedVMs)
	}

	logger.Info("")
	logger.Info("Guest agent channels have been added to all VMs")
	logger.Info("Running VMs will need to be restarted for changes to take effect")
	logger.Info("You can restart VMs with: eos update kvm --restart --name <vm-name>")

	return result, nil
}

// MakeBatches groups items into batches
func MakeBatches(items []string, batchSize int) [][]string {
	var batches [][]string
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}
		batches = append(batches, items[i:end])
	}
	return batches
}

// addGuestAgentChannel adds guest agent channel to a VM
func addGuestAgentChannel(rc *eos_io.RuntimeContext, vmName string, noBackup bool) (backupPath string, err error) {
	logger := otelzap.Ctx(rc.Ctx)

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return "", fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return "", fmt.Errorf("failed to lookup domain: %w", err)
	}
	defer domain.Free()

	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return "", fmt.Errorf("failed to get XML: %w", err)
	}

	// Create backup
	if !noBackup {
		backupPath, err = backupVMXML(rc, vmName, xmlDesc)
		if err != nil {
			return "", fmt.Errorf("failed to create backup: %w", err)
		}
		logger.Debug("Created XML backup", zap.String("backup", backupPath))
	}

	// Check if virtio-serial controller exists
	hasController := strings.Contains(xmlDesc, `type='virtio-serial'`) ||
		strings.Contains(xmlDesc, `type="virtio-serial"`)

	if !hasController {
		logger.Debug("Adding virtio-serial controller", zap.String("vm", vmName))

		controllerXML := `<controller type='virtio-serial' index='0'>
  <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
</controller>`

		if err := domain.AttachDeviceFlags(controllerXML, 1); err != nil {
			return backupPath, fmt.Errorf("failed to add virtio-serial controller: %w", err)
		}

		logger.Debug("Virtio-serial controller added", zap.String("vm", vmName))
	}

	// Add guest agent channel
	logger.Debug("Adding guest agent channel", zap.String("vm", vmName))

	channelXML := `<channel type='unix'>
  <source mode='bind'/>
  <target type='virtio' name='org.qemu.guest_agent.0'/>
  <address type='virtio-serial' controller='0' bus='0' port='1'/>
</channel>`

	if err := domain.AttachDeviceFlags(channelXML, 1); err != nil {
		return backupPath, fmt.Errorf("failed to add guest agent channel: %w", err)
	}

	logger.Debug("Guest agent channel added", zap.String("vm", vmName))

	return backupPath, nil
}

// backupVMXML creates a backup of VM XML
func backupVMXML(rc *eos_io.RuntimeContext, vmName, xmlContent string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	backupDir := "/var/lib/eos/backups/kvm"
	if err := os.MkdirAll(backupDir, shared.ServiceDirPerm); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s/%s-guest-agent-%s.xml", backupDir, vmName, timestamp)

	if err := os.WriteFile(backupPath, []byte(xmlContent), shared.SecretFilePerm); err != nil {
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	logger.Debug("VM XML backed up", zap.String("path", backupPath))
	return backupPath, nil
}

// restoreVMXML restores VM XML from backup
func restoreVMXML(rc *eos_io.RuntimeContext, vmName, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restoring VM XML from backup",
		zap.String("vm", vmName),
		zap.String("backup", backupPath))

	xmlBytes, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("failed to lookup domain: %w", err)
	}

	if err := domain.Undefine(); err != nil {
		domain.Free()
		return fmt.Errorf("failed to undefine domain: %w", err)
	}
	domain.Free()

	_, err = conn.DomainDefineXML(string(xmlBytes))
	if err != nil {
		return fmt.Errorf("failed to redefine domain: %w", err)
	}

	logger.Info("VM XML restored from backup", zap.String("vm", vmName))
	return nil
}

// verifyGuestAgentChannel verifies guest agent channel was added
func verifyGuestAgentChannel(ctx context.Context, vmName string) error {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("failed to lookup domain: %w", err)
	}
	defer domain.Free()

	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf("failed to get XML: %w", err)
	}

	if !strings.Contains(xmlDesc, "org.qemu.guest_agent.0") {
		return fmt.Errorf("guest agent channel not found in XML after update")
	}

	if !strings.Contains(xmlDesc, `type='virtio-serial'`) &&
		!strings.Contains(xmlDesc, `type="virtio-serial"`) {
		return fmt.Errorf("virtio-serial controller not found in XML after update")
	}

	return nil
}
