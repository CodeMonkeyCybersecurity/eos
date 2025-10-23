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

// CreateVolume creates a new CephFS volume using the SDK
func (c *CephClient) CreateVolume(rc *eos_io.RuntimeContext, opts *VolumeCreateOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Validate options and check if volume exists
	logger.Info("Assessing CephFS volume creation prerequisites",
		zap.String("volume", opts.Name))

	if opts.Name == "" {
		return eos_err.NewUserError("volume name is required")
	}

	// Check if volume already exists
	exists, err := c.VolumeExists(rc, opts.Name)
	if err != nil {
		return fmt.Errorf("failed to check if volume exists: %w", err)
	}
	if exists {
		return eos_err.NewUserError("volume '%s' already exists", opts.Name)
	}

	// Apply defaults
	if opts.ReplicationSize == 0 {
		opts.ReplicationSize = DefaultReplicationSize
	}
	if opts.PGNum == 0 {
		opts.PGNum = DefaultPGNum
	}

	// INTERVENE: Create the volume using mon command
	logger.Info("Creating CephFS volume",
		zap.String("volume", opts.Name),
		zap.String("dataPool", opts.DataPool),
		zap.Int("replication", opts.ReplicationSize))

	// Create volume using 'ceph fs volume create' command via mon
	cmd := map[string]interface{}{
		"prefix": "fs volume create",
		"name":   opts.Name,
	}

	// Add placement spec if data pool is specified
	if opts.DataPool != "" {
		cmd["placement"] = opts.DataPool
	}

	if err := c.executeMonCommand(rc, cmd); err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	// EVALUATE: Verify volume was created
	logger.Info("Verifying CephFS volume creation")

	if exists, err := c.VolumeExists(rc, opts.Name); err != nil {
		return fmt.Errorf("failed to verify volume creation: %w", err)
	} else if !exists {
		return fmt.Errorf("volume creation verification failed: volume not found")
	}

	logger.Info("CephFS volume created successfully",
		zap.String("volume", opts.Name))

	return nil
}

// DeleteVolume deletes a CephFS volume with optional safety snapshot
func (c *CephClient) DeleteVolume(rc *eos_io.RuntimeContext, volumeName string, skipSnapshot bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if volume exists
	logger.Info("Assessing CephFS volume deletion prerequisites",
		zap.String("volume", volumeName))

	exists, err := c.VolumeExists(rc, volumeName)
	if err != nil {
		return fmt.Errorf("failed to check if volume exists: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("volume '%s' does not exist", volumeName)
	}

	// SAFETY: Create snapshot before deletion unless explicitly skipped
	if !skipSnapshot {
		logger.Info("Creating safety snapshot before volume deletion")
		snapName := fmt.Sprintf("pre-delete-%s", time.Now().Format("20060102-150405"))

		snapOpts := &SnapshotCreateOptions{
			VolumeName:   volumeName,
			SnapshotName: snapName,
		}

		if err := c.CreateSnapshot(rc, snapOpts); err != nil {
			return eos_err.NewUserError("failed to create safety snapshot before deletion: %w\nUse --skip-snapshot flag to bypass", err)
		}

		logger.Info("Safety snapshot created successfully",
			zap.String("snapshot", snapName))
	}

	// INTERVENE: Delete the volume using mon command
	logger.Info("Deleting CephFS volume",
		zap.String("volume", volumeName))

	// Delete volume using 'ceph fs volume rm' command via mon
	cmd := map[string]interface{}{
		"prefix":      "fs volume rm",
		"vol_name":    volumeName,
		"yes_i_really_mean_it": true,
	}

	if err := c.executeMonCommand(rc, cmd); err != nil {
		return fmt.Errorf("failed to delete volume: %w", err)
	}

	// EVALUATE: Verify volume was deleted
	logger.Info("Verifying CephFS volume deletion")

	if exists, err := c.VolumeExists(rc, volumeName); err != nil {
		logger.Warn("Failed to verify volume deletion", zap.Error(err))
	} else if exists {
		return fmt.Errorf("volume deletion verification failed: volume still exists")
	}

	logger.Info("CephFS volume deleted successfully",
		zap.String("volume", volumeName))

	return nil
}

// ListVolumes lists all CephFS volumes
func (c *CephClient) ListVolumes(rc *eos_io.RuntimeContext) ([]*VolumeInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Listing CephFS volumes")

	// INTERVENE: Get volume list from FSAdmin
	volumeNames, err := c.fsAdmin.ListVolumes()
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	volumes := make([]*VolumeInfo, 0, len(volumeNames))

	// Get detailed info for each volume
	for _, name := range volumeNames {
		logger.Debug("Getting details for volume", zap.String("volume", name))

		info, err := c.GetVolumeInfo(rc, name)
		if err != nil {
			logger.Warn("Failed to get volume details, skipping",
				zap.String("volume", name),
				zap.Error(err))
			continue
		}

		volumes = append(volumes, info)
	}

	// EVALUATE
	logger.Info("Volume listing completed",
		zap.Int("volumeCount", len(volumes)))

	return volumes, nil
}

// GetVolumeInfo retrieves detailed information about a volume
func (c *CephClient) GetVolumeInfo(rc *eos_io.RuntimeContext, volumeName string) (*VolumeInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Getting volume information",
		zap.String("volume", volumeName))

	// ASSESS: Check if volume exists
	exists, err := c.VolumeExists(rc, volumeName)
	if err != nil {
		return nil, fmt.Errorf("failed to check if volume exists: %w", err)
	}
	if !exists {
		return nil, eos_err.NewUserError("volume '%s' does not exist", volumeName)
	}

	// INTERVENE: Get volume information using fsAdmin.FetchVolumeInfo()
	volInfo, err := c.fsAdmin.FetchVolumeInfo(volumeName)
	if err != nil {
		return nil, fmt.Errorf("failed to get volume info: %w", err)
	}

	// EVALUATE: Parse volume information from go-ceph SDK types
	// Extract data pool names
	dataPools := make([]string, 0, len(volInfo.Pools.DataPool))
	for _, pool := range volInfo.Pools.DataPool {
		dataPools = append(dataPools, pool.PoolName)
	}

	// Extract metadata pool names
	metadataPools := make([]string, 0, len(volInfo.Pools.MetadataPool))
	for _, pool := range volInfo.Pools.MetadataPool {
		metadataPools = append(metadataPools, pool.PoolName)
	}

	info := &VolumeInfo{
		Name:          volumeName,
		MetadataPools: metadataPools,
		DataPools:     dataPools,
		UsedSize:      int64(volInfo.UsedSize),
		// Size and other fields would require additional pool stat queries
	}

	logger.Debug("Volume info retrieved",
		zap.String("volume", volumeName),
		zap.Strings("dataPools", info.DataPools),
		zap.Strings("metadataPools", info.MetadataPools),
		zap.Int64("usedSize", info.UsedSize))

	return info, nil
}

// UpdateVolume updates volume configuration
func (c *CephClient) UpdateVolume(rc *eos_io.RuntimeContext, volumeName string, opts *VolumeUpdateOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if volume exists
	logger.Info("Assessing CephFS volume update prerequisites",
		zap.String("volume", volumeName))

	exists, err := c.VolumeExists(rc, volumeName)
	if err != nil {
		return fmt.Errorf("failed to check if volume exists: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("volume '%s' does not exist", volumeName)
	}

	// SAFETY: Create snapshot before update unless explicitly skipped
	if !opts.SkipSnapshot {
		logger.Info("Creating safety snapshot before volume update")
		snapName := fmt.Sprintf("pre-update-%s", time.Now().Format("20060102-150405"))

		snapOpts := &SnapshotCreateOptions{
			VolumeName:   volumeName,
			SnapshotName: snapName,
		}

		if err := c.CreateSnapshot(rc, snapOpts); err != nil {
			logger.Warn("Failed to create safety snapshot, continuing",
				zap.Error(err))
		} else {
			logger.Info("Safety snapshot created",
				zap.String("snapshot", snapName))
		}
	}

	// INTERVENE: Update volume settings
	logger.Info("Updating CephFS volume",
		zap.String("volume", volumeName))

	// Get volume info to know which pools to update
	volInfo, err := c.GetVolumeInfo(rc, volumeName)
	if err != nil {
		return fmt.Errorf("failed to get volume info: %w", err)
	}

	// Update replication if requested
	if opts.NewReplication > 0 {
		logger.Info("Updating volume replication size",
			zap.Int("newSize", opts.NewReplication))

		// Update replication for all data pools
		for _, poolName := range volInfo.DataPools {
			if err := c.setPoolSize(rc, poolName, opts.NewReplication); err != nil {
				return fmt.Errorf("failed to update replication for pool %s: %w", poolName, err)
			}
		}

		// Update metadata pool replication
		for _, poolName := range volInfo.MetadataPools {
			if err := c.setPoolSize(rc, poolName, opts.NewReplication); err != nil {
				return fmt.Errorf("failed to update replication for metadata pool %s: %w", poolName, err)
			}
		}
	}

	// TODO: Implement quota/size updates using subvolume resize
	// This would require knowing which subvolume to resize, or creating a default subvolume
	if opts.NewSize > 0 {
		logger.Warn("Volume size updates not yet implemented",
			zap.String("reason", "requires subvolume management"))
	}

	logger.Info("CephFS volume updated successfully",
		zap.String("volume", volumeName))

	return nil
}

// VolumeExists checks if a volume exists
func (c *CephClient) VolumeExists(rc *eos_io.RuntimeContext, volumeName string) (bool, error) {
	volumes, err := c.fsAdmin.ListVolumes()
	if err != nil {
		return false, fmt.Errorf("failed to list volumes: %w", err)
	}

	for _, name := range volumes {
		if name == volumeName {
			return true, nil
		}
	}

	return false, nil
}

// setPoolReplication sets the replication size for a pool
func (c *CephClient) setPoolReplication(rc *eos_io.RuntimeContext, poolName string, replicationSize int) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Setting pool replication",
		zap.String("pool", poolName),
		zap.Int("size", replicationSize))

	// Get IOContext for the pool
	ioctx, err := c.conn.OpenIOContext(poolName)
	if err != nil {
		return fmt.Errorf("failed to open pool context: %w", err)
	}
	defer ioctx.Destroy()

	// Note: Pool replication is set via mon commands, not via rados
	// We would need to use the mon command interface for this
	// For now, log and continue

	logger.Debug("Pool replication update requires mon command interface (not yet implemented)")

	return nil
}
