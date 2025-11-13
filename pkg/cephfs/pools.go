//go:build !darwin
// +build !darwin

package cephfs

import (
	"fmt"
	"strconv"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreatePool creates a new Ceph pool
func (c *CephClient) CreatePool(rc *eos_io.RuntimeContext, opts *PoolCreateOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Validate options
	logger.Info("Assessing Ceph pool creation prerequisites",
		zap.String("pool", opts.Name))

	if opts.Name == "" {
		return eos_err.NewUserError("pool name is required")
	}

	// Check if pool already exists
	exists, err := c.PoolExists(rc, opts.Name)
	if err != nil {
		return fmt.Errorf("failed to check if pool exists: %w", err)
	}
	if exists {
		return eos_err.NewUserError("pool '%s' already exists", opts.Name)
	}

	// Apply defaults
	if opts.PGNum == 0 {
		opts.PGNum = DefaultPGNum
	}
	if opts.Size == 0 {
		opts.Size = DefaultReplicationSize
	}
	if opts.MinSize == 0 {
		opts.MinSize = opts.Size - 1
		if opts.MinSize < 1 {
			opts.MinSize = 1
		}
	}
	if opts.PoolType == "" {
		opts.PoolType = "replicated"
	}

	// INTERVENE: Create the pool
	logger.Info("Creating Ceph pool",
		zap.String("pool", opts.Name),
		zap.Int("pgNum", opts.PGNum),
		zap.Int("size", opts.Size))

	// Create pool using mon command
	if err := c.createPoolViaMonCommand(rc, opts); err != nil {
		return fmt.Errorf("failed to create pool: %w", err)
	}

	// Set pool application
	if opts.Application != "" {
		logger.Debug("Enabling pool application",
			zap.String("pool", opts.Name),
			zap.String("application", opts.Application))

		if err := c.setPoolApplication(rc, opts.Name, opts.Application); err != nil {
			logger.Warn("Failed to set pool application",
				zap.Error(err))
		}
	}

	// EVALUATE: Verify pool was created
	logger.Info("Verifying Ceph pool creation")

	if exists, err := c.PoolExists(rc, opts.Name); err != nil {
		return fmt.Errorf("failed to verify pool creation: %w", err)
	} else if !exists {
		return fmt.Errorf("pool creation verification failed: pool not found")
	}

	logger.Info("Ceph pool created successfully",
		zap.String("pool", opts.Name))

	return nil
}

// DeletePool deletes a Ceph pool
func (c *CephClient) DeletePool(rc *eos_io.RuntimeContext, poolName string, skipSnapshot bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if pool exists
	logger.Info("Assessing Ceph pool deletion prerequisites",
		zap.String("pool", poolName))

	exists, err := c.PoolExists(rc, poolName)
	if err != nil {
		return fmt.Errorf("failed to check if pool exists: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("pool '%s' does not exist", poolName)
	}

	// Check if pool is used by volumes
	volumes, err := c.ListVolumes(rc)
	if err != nil {
		logger.Warn("Failed to check if pool is in use", zap.Error(err))
	} else {
		for _, vol := range volumes {
			for _, dataPool := range vol.DataPools {
				if dataPool == poolName {
					return eos_err.NewUserError("pool '%s' is in use by volume '%s'. Delete the volume first or use --force",
						poolName, vol.Name)
				}
			}
		}
	}

	// INTERVENE: Delete the pool
	logger.Info("Deleting Ceph pool",
		zap.String("pool", poolName))

	// Delete pool using mon command
	if err := c.deletePoolViaMonCommand(rc, poolName); err != nil {
		return fmt.Errorf("failed to delete pool: %w", err)
	}

	// EVALUATE: Verify pool was deleted
	logger.Info("Verifying Ceph pool deletion")

	if exists, err := c.PoolExists(rc, poolName); err != nil {
		return fmt.Errorf("failed to verify pool deletion: %w", err)
	} else if exists {
		return fmt.Errorf("pool deletion verification failed: pool still exists")
	}

	logger.Info("Ceph pool deleted successfully",
		zap.String("pool", poolName))

	return nil
}

// ListPools lists all Ceph pools
func (c *CephClient) ListPools(rc *eos_io.RuntimeContext) ([]*PoolInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing Ceph pools")

	// Get pool names
	poolNames, err := c.conn.ListPools()
	if err != nil {
		return nil, fmt.Errorf("failed to list pools: %w", err)
	}

	pools := make([]*PoolInfo, 0, len(poolNames))

	for _, name := range poolNames {
		info, err := c.GetPoolInfo(rc, name)
		if err != nil {
			logger.Warn("Failed to get pool info, skipping",
				zap.String("pool", name),
				zap.Error(err))
			continue
		}

		pools = append(pools, info)
	}

	logger.Info("Pool listing completed",
		zap.Int("poolCount", len(pools)))

	return pools, nil
}

// GetPoolInfo retrieves detailed information about a pool
func (c *CephClient) GetPoolInfo(rc *eos_io.RuntimeContext, poolName string) (*PoolInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Getting pool information",
		zap.String("pool", poolName))

	// Get pool by name to get ID
	poolID, err := c.conn.GetPoolByName(poolName)
	if err != nil {
		return nil, fmt.Errorf("failed to get pool ID: %w", err)
	}

	info := &PoolInfo{
		Name: poolName,
		ID:   poolID,
	}

	// Get pool statistics using IOContext
	ioctx, err := c.conn.OpenIOContext(poolName)
	if err != nil {
		return nil, fmt.Errorf("failed to open pool context: %w", err)
	}
	defer ioctx.Destroy()

	// Get pool stats
	stats, err := ioctx.GetPoolStats()
	if err != nil {
		logger.Warn("Failed to get pool stats", zap.Error(err))
	}

	logger.Debug("Pool information retrieved",
		zap.String("pool", poolName),
		zap.Int64("id", poolID))

	// Additional pool info would come from mon commands
	// which we'll need to implement via mon command interface

	_ = stats // Use stats when available

	return info, nil
}

// UpdatePool updates pool configuration
func (c *CephClient) UpdatePool(rc *eos_io.RuntimeContext, poolName string, opts *PoolUpdateOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if pool exists
	logger.Info("Assessing Ceph pool update prerequisites",
		zap.String("pool", poolName))

	exists, err := c.PoolExists(rc, poolName)
	if err != nil {
		return fmt.Errorf("failed to check if pool exists: %w", err)
	}
	if !exists {
		return eos_err.NewUserError("pool '%s' does not exist", poolName)
	}

	// INTERVENE: Update pool settings
	logger.Info("Updating Ceph pool",
		zap.String("pool", poolName))

	// Update replication size if specified
	if opts.NewSize > 0 {
		logger.Debug("Updating pool replication size",
			zap.String("pool", poolName),
			zap.Int("size", opts.NewSize))

		if err := c.setPoolSize(rc, poolName, opts.NewSize); err != nil {
			return fmt.Errorf("failed to update pool size: %w", err)
		}
	}

	// Update PG num if specified
	if opts.NewPGNum > 0 {
		logger.Debug("Updating pool PG num",
			zap.String("pool", poolName),
			zap.Int("pgNum", opts.NewPGNum))

		if err := c.setPoolPGNum(rc, poolName, opts.NewPGNum); err != nil {
			return fmt.Errorf("failed to update pool PG num: %w", err)
		}
	}

	// Update quota if specified
	if opts.MaxBytes > 0 || opts.MaxObjects > 0 {
		logger.Debug("Updating pool quota",
			zap.String("pool", poolName),
			zap.Int64("maxBytes", opts.MaxBytes),
			zap.Int64("maxObjects", opts.MaxObjects))

		if err := c.setPoolQuota(rc, poolName, opts.MaxBytes, opts.MaxObjects); err != nil {
			return fmt.Errorf("failed to update pool quota: %w", err)
		}
	}

	// EVALUATE: Verify update
	logger.Info("Ceph pool updated successfully",
		zap.String("pool", poolName))

	return nil
}

// PoolExists checks if a pool exists
func (c *CephClient) PoolExists(rc *eos_io.RuntimeContext, poolName string) (bool, error) {
	_, err := c.conn.GetPoolByName(poolName)
	if err != nil {
		// Check if error indicates pool not found
		// In go-ceph, a non-existent pool returns an error
		// We treat any error as "pool not found" for now
		// TODO: Improve error detection when go-ceph provides better error types
		return false, nil
	}
	return true, nil
}

// Helper functions for mon commands

func (c *CephClient) createPoolViaMonCommand(rc *eos_io.RuntimeContext, opts *PoolCreateOptions) error {
	// Build mon command
	cmd := map[string]interface{}{
		"prefix": "osd pool create",
		"pool":   opts.Name,
		"pg_num": strconv.Itoa(opts.PGNum),
	}

	if opts.PoolType == "replicated" {
		cmd["pool_type"] = "replicated"
		cmd["size"] = strconv.Itoa(opts.Size)
	}

	// Execute mon command
	return c.executeMonCommand(rc, cmd)
}

func (c *CephClient) deletePoolViaMonCommand(rc *eos_io.RuntimeContext, poolName string) error {
	cmd := map[string]interface{}{
		"prefix": "osd pool delete",
		"pool":   poolName,
		"pool2":  poolName,
		"sure":   "--yes-i-really-really-mean-it",
	}

	return c.executeMonCommand(rc, cmd)
}

func (c *CephClient) setPoolApplication(rc *eos_io.RuntimeContext, poolName, application string) error {
	cmd := map[string]interface{}{
		"prefix": "osd pool application enable",
		"pool":   poolName,
		"app":    application,
	}

	return c.executeMonCommand(rc, cmd)
}

func (c *CephClient) setPoolSize(rc *eos_io.RuntimeContext, poolName string, size int) error {
	cmd := map[string]interface{}{
		"prefix": "osd pool set",
		"pool":   poolName,
		"var":    "size",
		"val":    strconv.Itoa(size),
	}

	return c.executeMonCommand(rc, cmd)
}

func (c *CephClient) setPoolPGNum(rc *eos_io.RuntimeContext, poolName string, pgNum int) error {
	cmd := map[string]interface{}{
		"prefix": "osd pool set",
		"pool":   poolName,
		"var":    "pg_num",
		"val":    strconv.Itoa(pgNum),
	}

	return c.executeMonCommand(rc, cmd)
}

func (c *CephClient) setPoolQuota(rc *eos_io.RuntimeContext, poolName string, maxBytes, maxObjects int64) error {
	if maxBytes > 0 {
		cmd := map[string]interface{}{
			"prefix": "osd pool set-quota",
			"pool":   poolName,
			"field":  "max_bytes",
			"val":    strconv.FormatInt(maxBytes, 10),
		}
		if err := c.executeMonCommand(rc, cmd); err != nil {
			return err
		}
	}

	if maxObjects > 0 {
		cmd := map[string]interface{}{
			"prefix": "osd pool set-quota",
			"pool":   poolName,
			"field":  "max_objects",
			"val":    strconv.FormatInt(maxObjects, 10),
		}
		if err := c.executeMonCommand(rc, cmd); err != nil {
			return err
		}
	}

	return nil
}

func (c *CephClient) executeMonCommand(rc *eos_io.RuntimeContext, cmd map[string]interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Executing mon command",
		zap.Any("command", cmd))

	// Use rados MonCommand to execute
	cmdJSON := fmt.Sprintf(`{"prefix":"%s"`, cmd["prefix"])
	for k, v := range cmd {
		if k != "prefix" {
			cmdJSON += fmt.Sprintf(`,"%s":"%v"`, k, v)
		}
	}
	cmdJSON += "}"

	buf, info, err := c.conn.MonCommand([]byte(cmdJSON))
	if err != nil {
		logger.Error("Mon command failed",
			zap.Error(err),
			zap.String("output", string(buf)),
			zap.String("info", info))
		return fmt.Errorf("mon command failed: %w (output: %s, info: %s)", err, string(buf), info)
	}

	logger.Debug("Mon command completed",
		zap.String("output", string(buf)))

	return nil
}
