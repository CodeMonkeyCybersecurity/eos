//go:build linux

package disk

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

// Manager orchestrates disk resize operations
type Manager struct {
	transactionLog *TransactionLog
}

// NewManager creates a new disk manager
func NewManager() *Manager {
	return &Manager{
		transactionLog: NewTransactionLog(),
	}
}

// Resize performs a disk resize operation with full safety checks
func (m *Manager) Resize(ctx context.Context, req *ResizeRequest) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Starting disk resize operation",
		zap.String("vm", req.VMName),
		zap.String("size", req.SizeSpec))

	// Parse size specification
	change, err := ParseSizeChange(req.SizeSpec)
	if err != nil {
		return fmt.Errorf("invalid size specification: %w", err)
	}

	// Phase 1: ASSESS
	logger.Info("Phase 1: ASSESS - Analyzing VM configuration")
	assessment, err := Assess(ctx, req.VMName, change)
	if err != nil {
		return fmt.Errorf("assessment failed: %w", err)
	}

	// Safety check
	if !assessment.SafeToResize && !req.Force {
		return fmt.Errorf("resize blocked due to safety concerns (use --force to override)")
	}

	// Dry run - stop here
	if req.DryRun {
		logger.Info("Dry run complete - no changes made")
		return nil
	}

	// Start transaction
	tx := m.transactionLog.Begin(req.VMName, change.Bytes)
	defer func() { _ = m.transactionLog.Save(tx) }()

	// Phase 2: INTERVENE
	logger.Info("Phase 2: INTERVENE - Applying changes")

	// Step 1: Create backup if needed
	if !req.SkipBackup && (!assessment.BackupExists || assessment.BackupAge > 24*time.Hour) {
		logger.Info("Creating safety backup")
		backupPath, err := m.createBackup(ctx, assessment)
		if err != nil {
			tx.Error = fmt.Sprintf("backup failed: %v", err)
			return fmt.Errorf("backup failed: %w", err)
		}
		tx.RecordStep("backup", StepResult{
			Name:      "backup",
			StartTime: time.Now(),
			EndTime:   time.Now(),
			Success:   true,
			Data:      map[string]interface{}{"path": backupPath},
		})
		tx.BackupPath = backupPath
		logger.Info("Backup created", zap.String("path", backupPath))
	}

	// Step 2: Resize backing store
	logger.Info("Resizing disk image",
		zap.String("from", FormatBytes(assessment.CurrentSizeBytes)),
		zap.String("to", FormatBytes(assessment.RequestedSizeBytes)))

	if err := m.resizeBackingStore(ctx, assessment); err != nil {
		tx.Error = fmt.Sprintf("backing store resize failed: %v", err)
		return fmt.Errorf("backing store resize failed: %w", err)
	}
	tx.RecordStep("backing_store", StepResult{
		Name:      "backing_store_resize",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Success:   true,
		Data: map[string]interface{}{
			"old_size": assessment.CurrentSizeBytes,
			"new_size": assessment.RequestedSizeBytes,
		},
	})

	// Step 3: Guest filesystem operations (if VM is running and has guest agent)
	if assessment.State == "running" && assessment.HasGuestAgent && change.Bytes > 0 {
		logger.Info("Performing guest filesystem operations")
		if err := m.resizeGuestFilesystem(ctx, assessment); err != nil {
			logger.Warn("Guest filesystem resize failed - manual intervention may be required",
				zap.Error(err))
			// Don't fail the entire operation - the space is available, just not utilized
			tx.RecordStep("guest_filesystem", StepResult{
				Name:      "guest_filesystem_resize",
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			tx.RecordStep("guest_filesystem", StepResult{
				Name:      "guest_filesystem_resize",
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Success:   true,
			})
		}
	} else {
		logger.Info("Skipping guest filesystem operations",
			zap.String("reason", "VM not running or no guest agent"))
	}

	// Phase 3: EVALUATE
	if !req.SkipVerify {
		logger.Info("Phase 3: EVALUATE - Verifying changes")
		if err := m.verify(ctx, assessment); err != nil {
			tx.Error = fmt.Sprintf("verification failed: %v", err)
			return fmt.Errorf("verification failed: %w", err)
		}
		tx.RecordStep("verify", StepResult{
			Name:      "verification",
			StartTime: time.Now(),
			EndTime:   time.Now(),
			Success:   true,
		})
	}

	tx.Success = true
	endTime := time.Now()
	tx.EndTime = &endTime

	logger.Info("Disk resize completed successfully",
		zap.String("vm", req.VMName),
		zap.String("size", FormatBytes(assessment.RequestedSizeBytes)))

	return nil
}

func (m *Manager) resizeBackingStore(ctx context.Context, assessment *Assessment) error {
	logger := otelzap.Ctx(ctx)

	// Build qemu-img resize command
	sizeSpec := fmt.Sprintf("%d", assessment.RequestedSizeBytes)

	cmd := exec.CommandContext(ctx, "qemu-img", "resize", assessment.DiskPath, sizeSpec)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("qemu-img resize failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("qemu-img resize failed: %w\nOutput: %s", err, output)
	}

	logger.Debug("qemu-img resize succeeded", zap.String("output", string(output)))
	return nil
}

func (m *Manager) createBackup(ctx context.Context, assessment *Assessment) (string, error) {
	backup := &BackupManager{}
	return backup.Create(ctx, assessment.VMName, assessment.DiskPath)
}

func (m *Manager) resizeGuestFilesystem(ctx context.Context, assessment *Assessment) error {
	guest := &GuestManager{}
	return guest.ResizeFilesystem(ctx, assessment)
}

func (m *Manager) verify(ctx context.Context, assessment *Assessment) error {
	logger := otelzap.Ctx(ctx)

	// Verify disk image with qemu-img info
	cmd := exec.CommandContext(ctx, "qemu-img", "info", "--output=json", assessment.DiskPath)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to verify disk: %w", err)
	}

	var diskInfo struct {
		VirtualSize int64 `json:"virtual-size"`
	}

	if err := json.Unmarshal(output, &diskInfo); err != nil {
		return fmt.Errorf("failed to parse disk info: %w", err)
	}

	if diskInfo.VirtualSize != assessment.RequestedSizeBytes {
		return fmt.Errorf("size mismatch: expected %d, got %d",
			assessment.RequestedSizeBytes, diskInfo.VirtualSize)
	}

	logger.Info("Verification passed", zap.String("size", FormatBytes(diskInfo.VirtualSize)))
	return nil
}

// Rollback attempts to restore from backup
func (m *Manager) Rollback(ctx context.Context, vmName string) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Attempting rollback", zap.String("vm", vmName))

	tx := m.transactionLog.GetLatest(vmName)
	if tx == nil {
		return fmt.Errorf("no transaction found for %s", vmName)
	}

	if tx.BackupPath == "" {
		return fmt.Errorf("no backup available for rollback")
	}

	// Get VM disk path
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("VM not found: %w", err)
	}
	defer func() { _ = domain.Free() }()

	// Get current disk path (simplified)
	xmlDesc, err := domain.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf("failed to get VM XML: %w", err)
	}

	// Extract disk path (same logic as assessment)
	diskPathStart := strings.Index(xmlDesc, "<source file='")
	if diskPathStart == -1 {
		return fmt.Errorf("could not find disk path")
	}
	diskPathStart += len("<source file='")
	diskPathEnd := strings.Index(xmlDesc[diskPathStart:], "'")
	diskPath := xmlDesc[diskPathStart : diskPathStart+diskPathEnd]

	// Restore from backup
	logger.Info("Restoring from backup",
		zap.String("backup", tx.BackupPath),
		zap.String("target", diskPath))

	cmd := exec.CommandContext(ctx, "cp", "-f", tx.BackupPath, diskPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restore from backup failed: %w", err)
	}

	logger.Info("Rollback completed successfully")
	return nil
}
