//go:build !darwin
// +build !darwin

package cephfs

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

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

	// INTERVENE: Create the snapshot using fsAdmin
	logger.Info("Creating CephFS snapshot",
		zap.String("volume", opts.VolumeName),
		zap.String("snapshot", opts.SnapshotName))

	// Determine which subvolume to snapshot
	subvolume := opts.SubVolume
	if subvolume == "" {
		// No subvolume specified - use or create default subvolume
		logger.Debug("No subvolume specified, using default subvolume")
		defaultSv, err := c.getOrCreateDefaultSubVolume(rc, opts.VolumeName)
		if err != nil {
			return fmt.Errorf("failed to get default subvolume: %w", err)
		}
		subvolume = defaultSv
	}

	logger.Info("Creating snapshot",
		zap.String("volume", opts.VolumeName),
		zap.String("subvolume", subvolume),
		zap.String("snapshot", opts.SnapshotName))

	// Create snapshot using fsAdmin
	if err := c.fsAdmin.CreateSubVolumeSnapshot(opts.VolumeName, DefaultSubVolumeGroup, subvolume, opts.SnapshotName); err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	logger.Info("CephFS snapshot created successfully",
		zap.String("volume", opts.VolumeName),
		zap.String("subvolume", subvolume),
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

	// INTERVENE: Delete the snapshot using fsAdmin
	logger.Info("Deleting CephFS snapshot",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	// Determine which subvolume the snapshot belongs to
	targetSubvolume := subVolume
	if targetSubvolume == "" {
		// No subvolume specified - assume default subvolume
		defaultSv, err := c.getOrCreateDefaultSubVolume(rc, volumeName)
		if err != nil {
			return fmt.Errorf("failed to get default subvolume: %w", err)
		}
		targetSubvolume = defaultSv
	}

	logger.Info("Deleting snapshot",
		zap.String("volume", volumeName),
		zap.String("subvolume", targetSubvolume),
		zap.String("snapshot", snapshotName))

	// Delete snapshot using fsAdmin
	if err := c.fsAdmin.RemoveSubVolumeSnapshot(volumeName, DefaultSubVolumeGroup, targetSubvolume, snapshotName); err != nil {
		return fmt.Errorf("failed to delete snapshot: %w", err)
	}

	// EVALUATE: Verify deletion
	logger.Info("Verifying snapshot deletion")
	if exists, err := c.SnapshotExists(rc, volumeName, snapshotName, targetSubvolume); err != nil {
		logger.Warn("Failed to verify snapshot deletion", zap.Error(err))
	} else if exists {
		return fmt.Errorf("snapshot deletion verification failed: snapshot still exists")
	}

	logger.Info("CephFS snapshot deleted successfully",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	return nil
}

// ListSnapshots lists all snapshots for a volume/subvolume
func (c *CephClient) ListSnapshots(rc *eos_io.RuntimeContext, volumeName, subVolume string) ([]*SnapshotInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing CephFS snapshots",
		zap.String("volume", volumeName),
		zap.String("subvolume", subVolume))

	// Determine which subvolume to list snapshots for
	targetSubvolume := subVolume
	if targetSubvolume == "" {
		// No subvolume specified - check if default subvolume exists
		logger.Debug("No subvolume specified, checking for default subvolume")
		defaultSv, err := c.getOrCreateDefaultSubVolume(rc, volumeName)
		if err != nil {
			return nil, fmt.Errorf("failed to get default subvolume: %w", err)
		}
		targetSubvolume = defaultSv
	}

	// List snapshots using fsAdmin
	snapshotNames, err := c.fsAdmin.ListSubVolumeSnapshots(volumeName, DefaultSubVolumeGroup, targetSubvolume)
	if err != nil {
		return nil, fmt.Errorf("failed to list snapshots: %w", err)
	}

	snapshots := make([]*SnapshotInfo, 0, len(snapshotNames))
	for _, snapName := range snapshotNames {
		// Get detailed snapshot info
		info, err := c.GetSnapshotInfo(rc, volumeName, snapName, targetSubvolume)
		if err != nil {
			logger.Warn("Failed to get snapshot details, skipping",
				zap.String("snapshot", snapName),
				zap.Error(err))
			// Add basic info even if detailed fetch fails
			snapshots = append(snapshots, &SnapshotInfo{
				Name:       snapName,
				VolumeName: volumeName,
			})
			continue
		}
		snapshots = append(snapshots, info)
	}

	logger.Info("Snapshot listing completed",
		zap.String("volume", volumeName),
		zap.String("subvolume", targetSubvolume),
		zap.Int("count", len(snapshots)))

	return snapshots, nil
}

// GetSnapshotInfo retrieves detailed information about a snapshot
func (c *CephClient) GetSnapshotInfo(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) (*SnapshotInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Getting snapshot information",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	// Determine which subvolume the snapshot belongs to
	targetSubvolume := subVolume
	if targetSubvolume == "" {
		// No subvolume specified - assume default subvolume
		defaultSv, err := c.getOrCreateDefaultSubVolume(rc, volumeName)
		if err != nil {
			return nil, fmt.Errorf("failed to get default subvolume: %w", err)
		}
		targetSubvolume = defaultSv
	}

	// Get snapshot info using fsAdmin
	snapInfo, err := c.fsAdmin.SubVolumeSnapshotInfo(volumeName, DefaultSubVolumeGroup, targetSubvolume, snapshotName)
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot info: %w", err)
	}

	info := &SnapshotInfo{
		Name:       snapshotName,
		VolumeName: volumeName,
		CreatedAt:  snapInfo.CreatedAt.Time,
		Size:       int64(snapInfo.Size),
		Protected:  snapInfo.HasPendingClones == "yes", // Protected snapshots have this set
	}

	logger.Debug("Snapshot info retrieved",
		zap.String("snapshot", snapshotName),
		zap.Time("createdAt", info.CreatedAt),
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

	// Determine which subvolume the snapshot belongs to
	targetSubvolume := subVolume
	if targetSubvolume == "" {
		defaultSv, err := c.getOrCreateDefaultSubVolume(rc, volumeName)
		if err != nil {
			return fmt.Errorf("failed to get default subvolume: %w", err)
		}
		targetSubvolume = defaultSv
	}

	// Clone the snapshot to a temporary subvolume
	tempSubvolName := fmt.Sprintf("rollback-temp-%s", time.Now().Format("20060102-150405"))

	logger.Info("Cloning snapshot to temporary subvolume",
		zap.String("snapshot", snapshotName),
		zap.String("tempSubvol", tempSubvolName))

	// Create clone using fsAdmin
	if err := c.fsAdmin.CloneSubVolumeSnapshot(volumeName, DefaultSubVolumeGroup, targetSubvolume, snapshotName, tempSubvolName, nil); err != nil {
		return fmt.Errorf("failed to clone snapshot: %w", err)
	}

	// Wait for clone to complete
	logger.Info("Waiting for clone operation to complete")

	maxRetries := 60 // 5 minutes max (5 second intervals)
	for i := 0; i < maxRetries; i++ {
		status, err := c.fsAdmin.CloneStatus(volumeName, DefaultSubVolumeGroup, tempSubvolName)
		if err != nil {
			logger.Warn("Failed to check clone status", zap.Error(err))
			time.Sleep(5 * time.Second)
			continue
		}

		logger.Debug("Clone status check",
			zap.String("state", string(status.State)),
			zap.Int("attempt", i+1))

		if status.State == "complete" {
			logger.Info("Clone completed successfully")
			break
		} else if status.State == "failed" {
			// Cleanup temp subvolume on failure
			_ = c.fsAdmin.RemoveSubVolume(volumeName, DefaultSubVolumeGroup, tempSubvolName)
			return fmt.Errorf("clone operation failed")
		}

		time.Sleep(5 * time.Second)
	}

	// EVALUATE: Verify clone completed
	finalStatus, err := c.fsAdmin.CloneStatus(volumeName, DefaultSubVolumeGroup, tempSubvolName)
	if err != nil {
		return fmt.Errorf("failed to verify clone completion: %w", err)
	}

	if finalStatus.State != "complete" {
		logger.Error("Clone did not complete within timeout",
			zap.String("state", string(finalStatus.State)))
		return eos_err.NewUserError(
			"Snapshot clone timed out after 5 minutes.\n"+
				"Current state: %s\n"+
				"The temporary subvolume '%s' has been left in place for manual inspection.\n"+
				"To complete rollback manually:\n"+
				"  1. Wait for clone to complete: ceph fs clone status %s %s\n"+
				"  2. Remove old data from original subvolume\n"+
				"  3. Copy data from %s to %s\n"+
				"  4. Remove temp subvolume: ceph fs subvolume rm %s %s",
			finalStatus.State, tempSubvolName, volumeName, tempSubvolName,
			tempSubvolName, targetSubvolume, volumeName, tempSubvolName,
		)
	}

	logger.Info("Snapshot rollback completed successfully",
		zap.String("volume", volumeName),
		zap.String("subvolume", targetSubvolume),
		zap.String("snapshot", snapshotName),
		zap.String("tempClone", tempSubvolName))

	logger.Warn("Manual data restoration required",
		zap.String("message", fmt.Sprintf(
			"The snapshot has been cloned to temporary subvolume '%s'.\n"+
				"To complete rollback:\n"+
				"  1. Backup current data if needed\n"+
				"  2. Mount and copy data from clone to original location\n"+
				"  3. Delete temporary clone: eos delete ceph --snapshot %s --snapshot-volume %s",
			tempSubvolName, tempSubvolName, volumeName)))

	return nil
}

// ProtectSnapshot protects a snapshot from deletion
func (c *CephClient) ProtectSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Protecting CephFS snapshot",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	// Determine which subvolume the snapshot belongs to
	targetSubvolume := subVolume
	if targetSubvolume == "" {
		defaultSv, err := c.getOrCreateDefaultSubVolume(rc, volumeName)
		if err != nil {
			return fmt.Errorf("failed to get default subvolume: %w", err)
		}
		targetSubvolume = defaultSv
	}

	// Protect snapshot using fsAdmin
	if err := c.fsAdmin.ProtectSubVolumeSnapshot(volumeName, DefaultSubVolumeGroup, targetSubvolume, snapshotName); err != nil {
		return fmt.Errorf("failed to protect snapshot: %w", err)
	}

	logger.Info("Snapshot protected successfully",
		zap.String("volume", volumeName),
		zap.String("subvolume", targetSubvolume),
		zap.String("snapshot", snapshotName))

	return nil
}

// UnprotectSnapshot removes protection from a snapshot
func (c *CephClient) UnprotectSnapshot(rc *eos_io.RuntimeContext, volumeName, snapshotName, subVolume string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Unprotecting CephFS snapshot",
		zap.String("volume", volumeName),
		zap.String("snapshot", snapshotName))

	// Determine which subvolume the snapshot belongs to
	targetSubvolume := subVolume
	if targetSubvolume == "" {
		defaultSv, err := c.getOrCreateDefaultSubVolume(rc, volumeName)
		if err != nil {
			return fmt.Errorf("failed to get default subvolume: %w", err)
		}
		targetSubvolume = defaultSv
	}

	// Unprotect snapshot using fsAdmin
	if err := c.fsAdmin.UnprotectSubVolumeSnapshot(volumeName, DefaultSubVolumeGroup, targetSubvolume, snapshotName); err != nil {
		return fmt.Errorf("failed to unprotect snapshot: %w", err)
	}

	logger.Info("Snapshot unprotected successfully",
		zap.String("volume", volumeName),
		zap.String("subvolume", targetSubvolume),
		zap.String("snapshot", snapshotName))

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
