package disk_safety

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SnapshotManager handles LVM snapshot creation and management
type SnapshotManager struct {
	mu          sync.RWMutex
	journal     *JournalStorage
	snapshots   map[string]*Snapshot
	minSize     uint64
	maxSize     uint64
	keepTime    time.Duration
	autoCleanup bool
}

// NewSnapshotManager creates a new snapshot manager
func NewSnapshotManager(journal *JournalStorage) *SnapshotManager {
	return &SnapshotManager{
		journal:     journal,
		snapshots:   make(map[string]*Snapshot),
		minSize:     DefaultSnapshotMinSize,
		maxSize:     DefaultSnapshotMaxSize,
		keepTime:    DefaultSnapshotKeepTime,
		autoCleanup: true,
	}
}

// SetSizeLimits configures snapshot size constraints
func (sm *SnapshotManager) SetSizeLimits(minSize, maxSize uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.minSize = minSize
	sm.maxSize = maxSize
}

// SetKeepTime configures how long to keep snapshots
func (sm *SnapshotManager) SetKeepTime(keepTime time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.keepTime = keepTime
}

// CreateSnapshot creates a snapshot for the specified logical volume
func (sm *SnapshotManager) CreateSnapshot(ctx context.Context, vg, lv, journalID string) (*Snapshot, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Creating LVM snapshot",
		zap.String("volume_group", vg),
		zap.String("logical_volume", lv),
		zap.String("journal_id", journalID))

	// Check if LV exists and get its size
	lvSize, err := sm.getLVSize(ctx, vg, lv)
	if err != nil {
		return nil, fmt.Errorf("get LV size: %w", err)
	}

	// Calculate snapshot size
	snapSize := sm.calculateSnapSize(lvSize)
	
	// Check if VG has enough free space
	if err := sm.checkVGFreeSpace(ctx, vg, snapSize); err != nil {
		return nil, fmt.Errorf("insufficient space for snapshot: %w", err)
	}

	// Generate snapshot name
	snapName := fmt.Sprintf("%s-eos-snap-%s", lv, time.Now().Format("20060102-150405"))

	logger.Debug("Creating snapshot",
		zap.String("snapshot_name", snapName),
		zap.Uint64("snapshot_size_bytes", snapSize),
		zap.Uint64("source_lv_size_bytes", lvSize))

	// Create the snapshot
	cmd := exec.CommandContext(ctx, "lvcreate",
		"-L", fmt.Sprintf("%dB", snapSize),
		"-s",
		"-n", snapName,
		fmt.Sprintf("%s/%s", vg, lv))

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Snapshot creation failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return nil, fmt.Errorf("create snapshot failed: %s: %w", string(output), err)
	}

	// Create snapshot object
	snap := &Snapshot{
		Name:       snapName,
		SourceVG:   vg,
		SourceLV:   lv,
		Size:       int64(snapSize),
		Created:    time.Now(),
		JournalID:  journalID,
		AutoRemove: sm.autoCleanup,
	}
	
	// Set removal time if auto-cleanup is enabled
	if sm.autoCleanup {
		removeAt := time.Now().Add(sm.keepTime)
		snap.RemoveAt = &removeAt
	}

	// Store in memory
	sm.mu.Lock()
	sm.snapshots[snap.GetID()] = snap
	sm.mu.Unlock()

	// Schedule automatic cleanup if enabled
	if sm.autoCleanup {
		sm.scheduleCleanup(ctx, snap)
	}

	// Record in journal if provided
	if journalID != "" && sm.journal != nil {
		if err := sm.journal.AddSnapshot(journalID, snap); err != nil {
			logger.Warn("Failed to record snapshot in journal",
				zap.Error(err),
				zap.String("journal_id", journalID))
		}
	}

	logger.Info("Snapshot created successfully",
		zap.String("snapshot_name", snapName),
		zap.String("snapshot_path", fmt.Sprintf("/dev/%s/%s", vg, snapName)))

	return snap, nil
}

// RemoveSnapshot removes an LVM snapshot
func (sm *SnapshotManager) RemoveSnapshot(ctx context.Context, snap *Snapshot) error {
	logger := otelzap.Ctx(ctx)
	snapPath := fmt.Sprintf("/dev/%s/%s", snap.SourceVG, snap.Name)

	logger.Info("Removing LVM snapshot",
		zap.String("snapshot_name", snap.Name),
		zap.String("snapshot_path", snapPath))

	// Remove the LVM snapshot
	cmd := exec.CommandContext(ctx, "lvremove", "-f", snapPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Snapshot removal failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("remove snapshot failed: %s: %w", string(output), err)
	}

	// Remove from memory
	sm.mu.Lock()
	delete(sm.snapshots, snap.GetID())
	sm.mu.Unlock()

	logger.Info("Snapshot removed successfully", zap.String("snapshot_name", snap.Name))
	return nil
}

// ListSnapshots returns all managed snapshots
func (sm *SnapshotManager) ListSnapshots() []*Snapshot {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snapshots := make([]*Snapshot, 0, len(sm.snapshots))
	for _, snap := range sm.snapshots {
		snapshots = append(snapshots, snap)
	}

	return snapshots
}

// GetSnapshot retrieves a snapshot by ID
func (sm *SnapshotManager) GetSnapshot(id string) (*Snapshot, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	snap, exists := sm.snapshots[id]
	return snap, exists
}

// CleanupExpired removes expired snapshots
func (sm *SnapshotManager) CleanupExpired(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	
	sm.mu.RLock()
	var expiredSnapshots []*Snapshot
	cutoff := time.Now().Add(-sm.keepTime)
	
	for _, snap := range sm.snapshots {
		if snap.AutoRemove && snap.Created.Before(cutoff) {
			expiredSnapshots = append(expiredSnapshots, snap)
		}
	}
	sm.mu.RUnlock()

	if len(expiredSnapshots) == 0 {
		logger.Debug("No expired snapshots to clean up")
		return nil
	}

	logger.Info("Cleaning up expired snapshots", zap.Int("count", len(expiredSnapshots)))

	var cleanupErrors []error
	for _, snap := range expiredSnapshots {
		if err := sm.RemoveSnapshot(ctx, snap); err != nil {
			logger.Error("Failed to remove expired snapshot",
				zap.String("snapshot_name", snap.Name),
				zap.Error(err))
			cleanupErrors = append(cleanupErrors, err)
		}
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("failed to remove %d snapshots: %v", len(cleanupErrors), cleanupErrors)
	}

	logger.Info("Expired snapshots cleaned up successfully", zap.Int("count", len(expiredSnapshots)))
	return nil
}

// ScheduleCleanup schedules automatic cleanup for a snapshot
func (sm *SnapshotManager) ScheduleCleanup(ctx context.Context, snap *Snapshot, delay time.Duration) {
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-timer.C:
			if err := sm.RemoveSnapshot(ctx, snap); err != nil {
				logger := otelzap.Ctx(ctx)
				logger.Error("Scheduled snapshot cleanup failed",
					zap.String("snapshot_name", snap.Name),
					zap.Error(err))
			}
		case <-ctx.Done():
			return
		}
	}()
}

// GetSnapshotUsage returns snapshot usage statistics
func (sm *SnapshotManager) GetSnapshotUsage(ctx context.Context, snap *Snapshot) (*SnapshotUsage, error) {
	snapPath := fmt.Sprintf("%s/%s", snap.SourceVG, snap.Name)
	// Use lvs to get snapshot usage information
	cmd := exec.CommandContext(ctx, "lvs", "--noheadings", "--units", "b", "--separator", ":",
		"-o", "lv_name,data_percent,metadata_percent,lv_size", snapPath)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("get snapshot usage: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("no snapshot information found")
	}

	parts := strings.Split(strings.TrimSpace(lines[0]), ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid snapshot output format")
	}

	dataPercent, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	metadataPercent, _ := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	
	sizeStr := strings.TrimSpace(parts[3])
	sizeStr = strings.TrimSuffix(sizeStr, "B")
	size, _ := strconv.ParseUint(sizeStr, 10, 64)

	usage := &SnapshotUsage{
		SnapshotName:    snap.Name,
		DataPercent:     dataPercent,
		MetadataPercent: metadataPercent,
		Size:            size,
		UsedData:        uint64(float64(size) * dataPercent / 100.0),
		Timestamp:       time.Now(),
	}

	return usage, nil
}

// calculateSnapSize determines the appropriate snapshot size
func (sm *SnapshotManager) calculateSnapSize(lvSize uint64) uint64 {
	// Calculate 5% of LV size for snapshot
	snapSize := lvSize / 20

	// Enforce minimum size
	if snapSize < sm.minSize {
		snapSize = sm.minSize
	}

	// Enforce maximum size
	if snapSize > sm.maxSize {
		snapSize = sm.maxSize
	}

	return snapSize
}

// getLVSize gets the size of a logical volume in bytes
func (sm *SnapshotManager) getLVSize(ctx context.Context, vg, lv string) (uint64, error) {
	cmd := exec.CommandContext(ctx, "lvs", "--noheadings", "--units", "b", "--separator", ":",
		"-o", "lv_size", fmt.Sprintf("%s/%s", vg, lv))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("get LV size: %w", err)
	}

	sizeStr := strings.TrimSpace(string(output))
	sizeStr = strings.TrimSuffix(sizeStr, "B") // Remove 'B' suffix
	
	size, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse LV size: %w", err)
	}

	return size, nil
}

// checkVGFreeSpace verifies that the volume group has enough free space
func (sm *SnapshotManager) checkVGFreeSpace(ctx context.Context, vg string, requiredSize uint64) error {
	cmd := exec.CommandContext(ctx, "vgs", "--noheadings", "--units", "b", "--separator", ":",
		"-o", "vg_free", vg)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("get VG free space: %w", err)
	}

	freeStr := strings.TrimSpace(string(output))
	freeStr = strings.TrimSuffix(freeStr, "B")
	
	freeSpace, err := strconv.ParseUint(freeStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse VG free space: %w", err)
	}

	if freeSpace < requiredSize {
		return fmt.Errorf("insufficient free space in VG %s: need %d bytes, have %d bytes",
			vg, requiredSize, freeSpace)
	}

	return nil
}

// scheduleCleanup schedules automatic cleanup for a snapshot
func (sm *SnapshotManager) scheduleCleanup(ctx context.Context, snap *Snapshot) {
	go func() {
		timer := time.NewTimer(sm.keepTime)
		defer timer.Stop()

		select {
		case <-timer.C:
			if err := sm.RemoveSnapshot(ctx, snap); err != nil {
				logger := otelzap.Ctx(ctx)
				logger.Error("Automatic snapshot cleanup failed",
					zap.String("snapshot_name", snap.Name),
					zap.Error(err))
			}
		case <-ctx.Done():
			return
		}
	}()
}

// SnapshotUsage contains snapshot usage statistics
type SnapshotUsage struct {
	SnapshotName    string    `json:"snapshot_name"`
	DataPercent     float64   `json:"data_percent"`
	MetadataPercent float64   `json:"metadata_percent"`
	Size            uint64    `json:"size"`
	UsedData        uint64    `json:"used_data"`
	Timestamp       time.Time `json:"timestamp"`
}

// GetID returns a unique identifier for the snapshot
func (s *Snapshot) GetID() string {
	return fmt.Sprintf("%s/%s", s.SourceVG, s.Name)
}