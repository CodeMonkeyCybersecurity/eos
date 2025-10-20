package cephfs

import (
	"fmt"
	"time"

	"github.com/ceph/go-ceph/cephfs/admin"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SnapshotInfo represents information about a CephFS snapshot
type SnapshotInfo struct {
	Name       string
	VolumeName string
	CreatedAt  time.Time
	Size       int64 // Snapshot size (if available)
	Protected  bool  // Whether snapshot is protected from deletion
}

// SnapshotCreateOptions contains options for creating a snapshot
type SnapshotCreateOptions struct {
	VolumeName   string
	SnapshotName string
	SubVolume    string // Optional: snapshot a specific subvolume
}

// CreateSnapshot creates a new snapshot of a CephFS volume
func (c *CephClient) CreateSnapshot(rc *eos_io.RuntimeContext, opts *SnapshotCreateOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Validate options
	logger.Info("Assessing CephFS snapshot creation prerequisites",
		zap.String("volume", opts.VolumeName),
		zap.String("snapshot", opts.SnapshotName))

	if opts.VolumeName == "" {
		return eos_err.NewUserError("volume name is required")
	}
	if opts.SnapshotName == "" {
		return eos_err.NewUserError("snapshot name is required")
	}

	// Check if volume exists
	exists, err := c.VolumeExists(rc, opts.VolumeName)
	if err != nil {
		return fmt.Errorf("failed to check if volume exists: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("volume '%s' does not exist", opts.VolumeName)
	}

	// Check if snapshot already exists
	snapExists, err := c.SnapshotExists(rc, opts.VolumeName, opts.SnapshotName, opts.SubVolume)
	if err != nil {
		return fmt.Errorf("failed to check if snapshot exists: %w", err)
	}
	if snapExists {
		return eos_err.NewUserError("snapshot '%s' already exists for volume '%s'",
			opts.SnapshotName, opts.VolumeName)
	}

	// INTERVENE: Create the snapshot
	logger.Info("Creating CephFS snapshot",
		zap.String("volume", opts.VolumeName),
		zap.String("snapshot", opts.SnapshotName))

	// Build snapshot request
	snapSpec := &admin.SnapshotSpec{
		VolName:  opts.VolumeName,
		SnapName: opts.SnapshotName,
	}

	if opts.SubVolume != "" {
		snapSpec.SubVolName = opts.SubVolume
	}

	// Create snapshot via FSAdmin
	if err := c.fsAdmin.CreateSnapshotVolume(snapSpec); err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	// EVALUATE: Verify snapshot was created
	logger.Info("Verifying CephFS snapshot creation")

	time.Sleep(1 * time.Second)

	if exists, err := c.SnapshotExists(rc, opts.VolumeName, opts.SnapshotName, opts.SubVolume); err != nil {
		return fmt.Errorf("failed to verify snapshot creation: %w", err)
	} else if !exists {
		return fmt.Errorf("snapshot creation verification failed: snapshot not found")
	}

	logger.Info("CephFS snapshot created successfully",
		zap.String("volume", opts.VolumeName),
		zap.String("snapshot", opts.SnapshotName))

	return nil
}

// DeleteSnapshot deletes a CephFS snapshot
func (c *CephClient) DeleteSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if snapshot exists
	logger.Info("Assessing CephFS snapshot deletion prerequisites",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	exists, err := c.SnapshotExists(rc, volumeName, snapshotName, subVolume)
	if err != nil {
		return fmt.Errorf("failed to check if snapshot exists: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("snapshot '%s' does not exist for volume '%s'",
			snapshotName, volumeName)
	}

	// Check if snapshot is protected
	info, err := c.GetSnapshotInfo(rc, volumeName, snapshotName, subVolume)
	if err != nil {
		logger.Warn("Failed to get snapshot protection status",
			zap.Error(err))
	} else if info.Protected {
		return eos_err.NewUserError("snapshot '%s' is protected and cannot be deleted. Unprotect it first with: eos update ceph --snapshot %s --unprotect",
			snapshotName, snapshotName)
	}

	// INTERVENE: Delete the snapshot
	logger.Info("Deleting CephFS snapshot",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	// Build delete request
	snapSpec := &admin.SnapshotSpec{
		VolName:  volumeName,
		SnapName: snapshotName,
	}

	if subVolume != "" {
		snapSpec.SubVolName = subVolume
	}

	// Delete snapshot via FSAdmin
	if err := c.fsAdmin.RemoveSnapshotVolume(snapSpec); err != nil {
		return fmt.Errorf("failed to delete snapshot: %w", err)
	}

	// EVALUATE: Verify snapshot was deleted
	logger.Info("Verifying CephFS snapshot deletion")

	time.Sleep(1 * time.Second)

	if exists, err := c.SnapshotExists(rc, volumeName, snapshotName, subVolume); err != nil {
		return fmt.Errorf("failed to verify snapshot deletion: %w", err)
	} else if exists {
		return fmt.Errorf("snapshot deletion verification failed: snapshot still exists")
	}

	logger.Info("CephFS snapshot deleted successfully",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	return nil
}

// ListSnapshots lists all snapshots for a volume
func (c *CephClient) ListSnapshots(rc *eos_io.RuntimeContext, volumeName, subVolume string) ([]*SnapshotInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing CephFS snapshots",
		zap.String("volume", volumeName))

	// Get snapshot list from FSAdmin
	var snapInfoList []admin.SnapshotInfo
	var err error

	if subVolume != "" {
		snapInfoList, err = c.fsAdmin.ListSnapshots(volumeName, subVolume)
	} else {
		snapInfoList, err = c.fsAdmin.ListSnapshots(volumeName, "")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list snapshots: %w", err)
	}

	snapshots := make([]*SnapshotInfo, 0, len(snapInfoList))

	for _, snap := range snapInfoList {
		info := &SnapshotInfo{
			Name:       snap.Name,
			VolumeName: volumeName,
			CreatedAt:  snap.CreatedAt,
			Protected:  snap.Protected,
		}

		// Get additional info if available
		if snap.Size > 0 {
			info.Size = snap.Size
		}

		snapshots = append(snapshots, info)
	}

	logger.Info("Snapshot listing completed",
		zap.String("volume", volumeName),
		zap.Int("snapshotCount", len(snapshots)))

	return snapshots, nil
}

// GetSnapshotInfo retrieves detailed information about a snapshot
func (c *CephClient) GetSnapshotInfo(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) (*SnapshotInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Getting snapshot information",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	// Get snapshot info from FSAdmin
	snapSpec := &admin.SnapshotSpec{
		VolName:  volumeName,
		SnapName: snapshotName,
	}

	if subVolume != "" {
		snapSpec.SubVolName = subVolume
	}

	snapInfo, err := c.fsAdmin.SnapshotInfo(snapSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot info: %w", err)
	}

	info := &SnapshotInfo{
		Name:       snapshotName,
		VolumeName: volumeName,
		CreatedAt:  snapInfo.CreatedAt,
		Size:       snapInfo.Size,
		Protected:  snapInfo.Protected,
	}

	logger.Debug("Snapshot information retrieved",
		zap.String("snapshot", snapshotName),
		zap.Int64("size", info.Size))

	return info, nil
}

// RollbackToSnapshot rolls back a volume to a specific snapshot
func (c *CephClient) RollbackToSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if snapshot exists
	logger.Info("Assessing CephFS snapshot rollback prerequisites",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	exists, err := c.SnapshotExists(rc, volumeName, snapshotName, subVolume)
	if err != nil {
		return fmt.Errorf("failed to check if snapshot exists: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("snapshot '%s' does not exist for volume '%s'",
			snapshotName, volumeName)
	}

	// SAFETY: Create a snapshot of current state before rollback
	logger.Info("Creating safety snapshot of current state before rollback")
	preRollbackSnapName := fmt.Sprintf("pre-rollback-%s", time.Now().Format("20060102-150405"))

	preRollbackOpts := &SnapshotCreateOptions{
		VolumeName:   volumeName,
		SnapshotName: preRollbackSnapName,
		SubVolume:    subVolume,
	}

	if err := c.CreateSnapshot(rc, preRollbackOpts); err != nil {
		return fmt.Errorf("failed to create safety snapshot before rollback: %w", err)
	}

	logger.Info("Safety snapshot created before rollback",
		zap.String("snapshot", preRollbackSnapName))

	// INTERVENE: Perform rollback
	logger.Info("Rolling back CephFS volume to snapshot",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	// Note: CephFS snapshot rollback is done by restoring snapshot data
	// This requires admin API calls that may not be directly supported
	// We'll use the clone and swap method

	// 1. Clone the snapshot to a temporary volume
	tempVolName := fmt.Sprintf("%s-rollback-temp-%d", volumeName, time.Now().Unix())

	cloneOpts := &admin.CloneOptions{
		VolName:     volumeName,
		SubVolName:  subVolume,
		SnapName:    snapshotName,
		TargetName:  tempVolName,
		TargetGroup: "",
	}

	logger.Debug("Cloning snapshot to temporary volume",
		zap.String("tempVolume", tempVolName))

	if err := c.fsAdmin.CloneSnapshot(cloneOpts); err != nil {
		return fmt.Errorf("failed to clone snapshot: %w", err)
	}

	// Wait for clone to complete
	logger.Debug("Waiting for clone operation to complete")
	time.Sleep(5 * time.Second)

	// 2. Check clone status
	cloneStatus, err := c.fsAdmin.CloneStatus(volumeName, subVolume, tempVolName)
	if err != nil {
		return fmt.Errorf("failed to check clone status: %w", err)
	}

	logger.Debug("Clone status",
		zap.String("state", string(cloneStatus.State)))

	// TODO: Implement actual data swap/restore logic
	// This would require moving data from temp volume back to original volume
	// For now, log warning that full rollback is not yet implemented

	logger.Warn("Full snapshot rollback not yet fully implemented. Clone created at: " + tempVolName)
	logger.Info("To complete rollback manually:")
	logger.Info("  1. Unmount original volume")
	logger.Info("  2. Rename volumes: mv " + volumeName + " " + volumeName + "-old")
	logger.Info("  3. Rename clone: mv " + tempVolName + " " + volumeName)
	logger.Info("  4. Remount volume")

	return fmt.Errorf("snapshot rollback not fully implemented yet - clone created at %s", tempVolName)
}

// ProtectSnapshot protects a snapshot from deletion
func (c *CephClient) ProtectSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Protecting CephFS snapshot",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	snapSpec := &admin.SnapshotSpec{
		VolName:  volumeName,
		SnapName: snapshotName,
	}

	if subVolume != "" {
		snapSpec.SubVolName = subVolume
	}

	if err := c.fsAdmin.ProtectSnapshot(snapSpec); err != nil {
		return fmt.Errorf("failed to protect snapshot: %w", err)
	}

	logger.Info("Snapshot protected successfully")
	return nil
}

// UnprotectSnapshot removes protection from a snapshot
func (c *CephClient) UnprotectSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Unprotecting CephFS snapshot",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	snapSpec := &admin.SnapshotSpec{
		VolName:  volumeName,
		SnapName: snapshotName,
	}

	if subVolume != "" {
		snapSpec.SubVolName = subVolume
	}

	if err := c.fsAdmin.UnprotectSnapshot(snapSpec); err != nil {
		return fmt.Errorf("failed to unprotect snapshot: %w", err)
	}

	logger.Info("Snapshot unprotected successfully")
	return nil
}

// SnapshotExists checks if a snapshot exists
func (c *CephClient) SnapshotExists(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) (bool, error) {
	snapshots, err := c.ListSnapshots(rc, volumeName, subVolume)
	if err != nil {
		return false, fmt.Errorf("failed to list snapshots: %w", err)
	}

	for _, snap := range snapshots {
		if snap.Name == snapshotName {
			return true, nil
		}
	}

	return false, nil
}
