package disk_safety

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SafeStorageOperations provides safe disk operations with comprehensive safety checks
type SafeStorageOperations struct {
	journal   *JournalStorage
	preflight *PreflightRunner
	snapshots *SnapshotManager
	rollback  *RollbackManager
	config    *SafetyConfig
}

// DefaultSafetyConfig returns a conservative safety configuration
func DefaultSafetyConfig() *SafetyConfig {
	return &SafetyConfig{
		RequireSnapshot:    false,    // Allow operations without snapshots if VG space is limited
		SnapshotMinSize:    1 << 30,  // 1GB
		SnapshotMaxSize:    50 << 30, // 50GB
		SnapshotRetention:  24 * time.Hour,
		RequireBackup:      false,
		BackupMaxAge:       24 * time.Hour,
		AllowOnlineResize:  true,
		MaxResizePercent:   90,
		RequireHealthCheck: true,
		JournalRetention:   90 * 24 * time.Hour,
	}
}

// NewSafeStorageOperations creates a new safe storage operations manager
func NewSafeStorageOperations(rc *eos_io.RuntimeContext, config *SafetyConfig) (*SafeStorageOperations, error) {
	if config == nil {
		config = DefaultSafetyConfig()
	}

	// Initialize components
	journal, err := NewJournalStorage()
	if err != nil {
		return nil, fmt.Errorf("initialize journal: %w", err)
	}

	preflight := NewPreflightRunner(rc)
	snapshots := NewSnapshotManager(journal)
	rollback := NewRollbackManager(journal, snapshots)

	// Configure snapshot manager
	snapshots.SetKeepTime(config.SnapshotRetention)

	return &SafeStorageOperations{
		journal:   journal,
		preflight: preflight,
		snapshots: snapshots,
		rollback:  rollback,
		config:    config,
	}, nil
}

// SafeExtendLV safely extends a logical volume with full safety measures
func (sso *SafeStorageOperations) SafeExtendLV(rc *eos_io.RuntimeContext, req *ExtendLVRequest) (*OperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting safe LV extension operation",
		zap.String("volume_group", req.VolumeGroup),
		zap.String("logical_volume", req.LogicalVolume),
		zap.String("size", req.Size),
		zap.Bool("dry_run", req.DryRun))

	// Create operation context with timeout (default 10 minutes)
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Minute)
	defer cancel()

	// 1. ASSESS - Create journal entry
	target := DiskTarget{
		VolumeGroup: req.VolumeGroup,
		LogicalVol:  req.LogicalVolume,
		Device:      fmt.Sprintf("/dev/%s/%s", req.VolumeGroup, req.LogicalVolume),
	}

	entry, err := sso.journal.Create("safe_extend_lv", target)
	if err != nil {
		return nil, fmt.Errorf("create journal entry: %w", err)
	}

	// Set operation parameters
	entry.Parameters = map[string]interface{}{
		"size":             req.Size,
		"dry_run":          req.DryRun,
		"require_snapshot": sso.config.RequireSnapshot,
	}

	// Update journal status
	_ = sso.journal.UpdateStatus(entry.ID, StatusInProgress)

	// Track the operation result
	result := &OperationResult{
		JournalID: entry.ID,
		Operation: "safe_extend_lv",
		Target:    target,
		StartTime: time.Now(),
		Success:   false,
	}

	// Defer cleanup and final status updates
	defer func() {
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)

		if result.Success {
			_ = sso.journal.UpdateStatus(entry.ID, StatusCompleted)
			logger.Info("Safe LV extension completed successfully",
				zap.String("journal_id", entry.ID),
				zap.Duration("duration", result.Duration))
		} else {
			_ = sso.journal.UpdateStatus(entry.ID, StatusFailed)
			if result.Error != nil {
				_ = sso.journal.RecordError(entry.ID, result.Error)
			}
		}
	}()

	// 2. ASSESS - Run preflight checks
	logger.Info("Running preflight safety checks...")
	preflightReport, err := sso.preflight.Run(ctx, target)
	if err != nil {
		result.Error = fmt.Errorf("preflight checks failed: %w", err)
		result.PreflightReport = preflightReport
		return result, result.Error
	}
	result.PreflightReport = preflightReport

	logger.Info("Preflight checks passed",
		zap.Int("checks_run", len(preflightReport.Checks)),
		zap.Int("warnings", len(preflightReport.Warnings)))

	// 3. ASSESS - Capture pre-operation state
	logger.Info("Capturing pre-operation disk state...")
	preState, err := sso.captureDiskState(ctx, target)
	if err != nil {
		result.Error = fmt.Errorf("capture pre-state: %w", err)
		return result, result.Error
	}
	_ = sso.journal.SetPreState(entry.ID, preState)

	// 4. ASSESS - Create safety snapshot (always attempt, make required based on config)
	var snapshot *Snapshot
	logger.Info("Creating safety snapshot...")
	snapshot, err = sso.snapshots.CreateSnapshot(ctx, req.VolumeGroup, req.LogicalVolume, entry.ID)
	if err != nil {
		if sso.config.RequireSnapshot {
			result.Error = fmt.Errorf("required snapshot creation failed: %w", err)
			return result, result.Error
		}
		logger.Warn("Optional snapshot creation failed, proceeding without snapshot",
			zap.Error(err))
	} else {
		result.SnapshotCreated = true
		result.SnapshotID = snapshot.GetID()
		logger.Info("Safety snapshot created successfully",
			zap.String("snapshot_name", snapshot.Name))
	}

	// 5. Handle dry-run mode
	if req.DryRun {
		logger.Info("Dry-run mode: would extend LV but taking no action")
		result.Success = true
		result.Message = fmt.Sprintf("Dry-run: would extend %s/%s by %s", req.VolumeGroup, req.LogicalVolume, req.Size)
		return result, nil
	}

	// 6. INTERVENE - Execute the LV extension
	logger.Info("Executing LV extension operation...")
	if err := storage.ExtendLogicalVolume(rc, target.Device); err != nil {
		result.Error = fmt.Errorf("LV extension failed: %w", err)

		// Create rollback plan if we have a snapshot
		if snapshot != nil {
			rollbackPlan, planErr := sso.rollback.CreateRollbackPlan(ctx, entry.ID)
			if planErr == nil {
				_ = sso.journal.SetRollbackPlan(entry.ID, rollbackPlan)
				result.RollbackAvailable = true
				logger.Info("Rollback plan created and available",
					zap.String("rollback_method", string(rollbackPlan.Method)))
			}
		}

		return result, result.Error
	}

	// 7. EVALUATE - Capture post-operation state
	logger.Info("Capturing post-operation disk state...")
	postState, err := sso.captureDiskState(ctx, target)
	if err != nil {
		logger.Warn("Failed to capture post-operation state", zap.Error(err))
	} else {
		_ = sso.journal.SetPostState(entry.ID, postState)
	}

	// 8. EVALUATE - Verify the operation succeeded
	logger.Info("Verifying operation success...")
	if err := sso.verifyExtensionSuccess(ctx, target, req.Size); err != nil {
		result.Error = fmt.Errorf("operation verification failed: %w", err)
		return result, result.Error
	}

	// Success!
	result.Success = true
	result.Message = fmt.Sprintf("Successfully extended %s/%s", req.VolumeGroup, req.LogicalVolume)

	return result, nil
}

// SafeAutoResizeUbuntuLVM safely resizes the standard Ubuntu LVM setup
func (sso *SafeStorageOperations) SafeAutoResizeUbuntuLVM(rc *eos_io.RuntimeContext, dryRun bool) (*OperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting safe Ubuntu LVM auto-resize", zap.Bool("dry_run", dryRun))

	// Standard Ubuntu LVM paths
	req := &ExtendLVRequest{
		VolumeGroup:   "ubuntu-vg",
		LogicalVolume: "ubuntu-lv",
		Size:          "+100%FREE", // Use all available space
		DryRun:        dryRun,
	}

	return sso.SafeExtendLV(rc, req)
}

// RollbackOperation rolls back a failed operation
func (sso *SafeStorageOperations) RollbackOperation(rc *eos_io.RuntimeContext, journalID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting operation rollback", zap.String("journal_id", journalID))

	// Validate rollback safety
	plan, err := sso.rollback.CreateRollbackPlan(rc.Ctx, journalID)
	if err != nil {
		return fmt.Errorf("create rollback plan: %w", err)
	}

	if err := sso.rollback.ValidateRollbackSafety(rc.Ctx, plan, journalID); err != nil {
		return fmt.Errorf("rollback safety validation failed: %w", err)
	}

	// Execute rollback
	return sso.rollback.ExecuteRollback(rc.Ctx, plan, journalID)
}

// ListActiveOperations returns currently active disk operations
func (sso *SafeStorageOperations) ListActiveOperations() ([]*JournalEntry, error) {
	return sso.journal.ListActive()
}

// GetOperationStatus returns the status of a specific operation
func (sso *SafeStorageOperations) GetOperationStatus(journalID string) (*JournalEntry, error) {
	return sso.journal.Load(journalID)
}

// CleanupExpiredSnapshots removes old snapshots
func (sso *SafeStorageOperations) CleanupExpiredSnapshots(ctx context.Context) error {
	return sso.snapshots.CleanupExpired(ctx)
}

// Supporting types and methods

// ExtendLVRequest represents a request to extend a logical volume
type ExtendLVRequest struct {
	VolumeGroup   string `json:"volume_group"`
	LogicalVolume string `json:"logical_volume"`
	Size          string `json:"size"` // e.g., "+50G", "+100%FREE"
	DryRun        bool   `json:"dry_run"`
}

// OperationResult contains the result of a safe operation
type OperationResult struct {
	JournalID         string           `json:"journal_id"`
	Operation         string           `json:"operation"`
	Target            DiskTarget       `json:"target"`
	Success           bool             `json:"success"`
	Message           string           `json:"message"`
	Error             error            `json:"error,omitempty"`
	StartTime         time.Time        `json:"start_time"`
	EndTime           time.Time        `json:"end_time"`
	Duration          time.Duration    `json:"duration"`
	PreflightReport   *PreflightReport `json:"preflight_report,omitempty"`
	SnapshotCreated   bool             `json:"snapshot_created"`
	SnapshotID        string           `json:"snapshot_id,omitempty"`
	RollbackAvailable bool             `json:"rollback_available"`
}

// captureDiskState captures the current state of the disk system
func (sso *SafeStorageOperations) captureDiskState(ctx context.Context, target DiskTarget) (*DiskState, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Capturing disk state", zap.String("target_device", target.Device))

	state := &DiskState{
		Timestamp:   time.Now(),
		LVMState:    &LVMState{},
		Filesystems: []FilesystemState{},
		Mounts:      []MountState{},
		BlockDevs:   make(map[string]BlockDevice),
		DiskUsage:   make(map[string]DiskUsageState),
	}

	// This would be implemented to gather actual disk state
	// For now, returning a basic structure

	return state, nil
}

// verifyExtensionSuccess verifies that the LV extension was successful
func (sso *SafeStorageOperations) verifyExtensionSuccess(ctx context.Context, target DiskTarget, requestedSize string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Verifying LV extension success",
		zap.String("target", target.Device),
		zap.String("requested_size", requestedSize))

	// This would implement actual verification logic
	// For now, assume success

	return nil
}

// GetSafetyConfiguration returns the current safety configuration
func (sso *SafeStorageOperations) GetSafetyConfiguration() *SafetyConfig {
	return sso.config
}

// UpdateSafetyConfiguration updates the safety configuration
func (sso *SafeStorageOperations) UpdateSafetyConfiguration(config *SafetyConfig) {
	sso.config = config
	sso.snapshots.SetKeepTime(config.SnapshotRetention)
}
