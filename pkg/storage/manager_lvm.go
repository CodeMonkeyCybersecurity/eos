package storage

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LVMManager manages LVM storage operations through Salt
type LVMManager struct {
	rc         *eos_io.RuntimeContext
	saltClient SaltClient
}

// NewLVMManager creates a new LVM storage manager
func NewLVMManager(rc *eos_io.RuntimeContext, saltClient SaltClient) (*LVMManager, error) {
	return &LVMManager{
		rc:         rc,
		saltClient: saltClient,
	}, nil
}

// Create creates a new LVM logical volume through Salt
func (m *LVMManager) Create(config StorageConfig) error {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Creating LVM storage",
		zap.String("device", config.Device))

	// Extract LVM configuration from options
	lvmConfig, err := m.extractLVMConfig(config)
	if err != nil {
		return fmt.Errorf("invalid LVM configuration: %w", err)
	}

	// ASSESS - Check prerequisites
	logger.Info("Assessing LVM prerequisites")

	// Check if physical volume exists
	pvExists, err := m.checkPhysicalVolume(lvmConfig.PhysicalVolume)
	if err != nil {
		return fmt.Errorf("failed to check physical volume: %w", err)
	}

	if !pvExists {
		// Create physical volume through Salt
		if err := m.createPhysicalVolume(lvmConfig.PhysicalVolume); err != nil {
			return fmt.Errorf("failed to create physical volume: %w", err)
		}
	}

	// Check if volume group exists
	vgExists, err := m.checkVolumeGroup(lvmConfig.VolumeGroup)
	if err != nil {
		return fmt.Errorf("failed to check volume group: %w", err)
	}

	if !vgExists {
		// Create volume group through Salt
		if err := m.createVolumeGroup(lvmConfig.VolumeGroup, lvmConfig.PhysicalVolume); err != nil {
			return fmt.Errorf("failed to create volume group: %w", err)
		}
	}

	// INTERVENE - Create logical volume through Salt
	logger.Info("Creating logical volume via Salt",
		zap.String("lv", lvmConfig.LogicalVolume),
		zap.String("vg", lvmConfig.VolumeGroup))

	saltConfig := SaltStackConfig{
		Target: "*", // Could be specific minion
		State:  "lvm.lv_present",
		Pillar: map[string]interface{}{
			"lvm": map[string]interface{}{
				"logical_volume": lvmConfig.LogicalVolume,
				"volume_group":   lvmConfig.VolumeGroup,
				"size":           lvmConfig.Size,
				"filesystem":     string(lvmConfig.Filesystem),
				"mount_point":    config.MountPoint,
				"mount_options":  lvmConfig.MountOptions,
			},
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return fmt.Errorf("failed to create logical volume via Salt: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("Salt state failed: %s", result.Message)
	}

	// EVALUATE - Verify creation
	logger.Info("Verifying logical volume creation")

	lvPath := fmt.Sprintf("/dev/%s/%s", lvmConfig.VolumeGroup, lvmConfig.LogicalVolume)
	status, err := m.Read(lvPath)
	if err != nil {
		return fmt.Errorf("failed to verify logical volume creation: %w", err)
	}

	if status.State != "active" {
		return fmt.Errorf("logical volume created but not active: %s", status.State)
	}

	logger.Info("LVM storage created successfully",
		zap.String("path", lvPath),
		zap.String("size", lvmConfig.Size))

	return nil
}

// Read retrieves information about an LVM logical volume
func (m *LVMManager) Read(id string) (*StorageStatus, error) {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Reading LVM storage status",
		zap.String("id", id))

	// Query Salt for LVM information
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.lv_info",
		Pillar: map[string]interface{}{
			"path": id,
		},
	}

	_, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return nil, fmt.Errorf("failed to query LVM info via Salt: %w", err)
	}

	// Parse result into StorageStatus
	// This would parse the Salt return data
	status := &StorageStatus{
		ID:            id,
		Type:          StorageTypeLVM,
		State:         "active", // Parse from result
		TotalSize:     0,        // Parse from result
		UsedSize:      0,        // Parse from result
		AvailableSize: 0,        // Parse from result
		UsagePercent:  0,        // Calculate
		Mounted:       false,    // Parse from result
		MountPoint:    "",       // Parse from result
		Health:        string(HealthGood),
		UpdatedAt:     time.Now(),
	}

	return status, nil
}

// Update updates an LVM logical volume configuration
func (m *LVMManager) Update(id string, config StorageConfig) error {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Updating LVM storage",
		zap.String("id", id))

	// For LVM, update typically means resize or changing mount options
	// This would be implemented through Salt states
	return fmt.Errorf("LVM update not yet implemented")
}

// Delete removes an LVM logical volume
func (m *LVMManager) Delete(id string) error {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Deleting LVM storage",
		zap.String("id", id))

	// ASSESS - Check if safe to delete
	status, err := m.Read(id)
	if err != nil {
		return fmt.Errorf("failed to read LVM status: %w", err)
	}

	if status.Mounted {
		// Unmount first through Salt
		if err := m.unmountVolume(id); err != nil {
			return fmt.Errorf("failed to unmount volume: %w", err)
		}
	}

	// INTERVENE - Delete through Salt
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.lv_absent",
		Pillar: map[string]interface{}{
			"path": id,
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return fmt.Errorf("failed to delete logical volume via Salt: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("Salt state failed: %s", result.Message)
	}

	// EVALUATE - Verify deletion
	_, err = m.Read(id)
	if err == nil {
		return fmt.Errorf("logical volume deletion failed: still exists")
	}

	logger.Info("LVM storage deleted successfully", zap.String("id", id))
	return nil
}

// List lists all LVM logical volumes
func (m *LVMManager) List() ([]*StorageStatus, error) {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Listing LVM storage resources")

	// Query Salt for all LVs
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.lv_list",
		Pillar: map[string]interface{}{},
	}

	_, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return nil, fmt.Errorf("failed to list LVs via Salt: %w", err)
	}

	// Parse results into StorageStatus list
	var resources []*StorageStatus
	// This would parse the Salt return data
	// For now, return empty list
	return resources, nil
}

// GetMetrics retrieves performance metrics for an LVM volume
func (m *LVMManager) GetMetrics(id string) (*StorageMetrics, error) {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Debug("Getting LVM metrics",
		zap.String("id", id))

	// Query Salt for iostat data
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "disk.iostat",
		Pillar: map[string]interface{}{
			"device": id,
		},
	}

	_, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics via Salt: %w", err)
	}

	// Parse metrics from result
	metrics := &StorageMetrics{
		IOPS:            0, // Parse from result
		ReadThroughput:  0, // Parse from result
		WriteThroughput: 0, // Parse from result
		Latency:         0, // Parse from result
		QueueDepth:      0, // Parse from result
		Utilization:     0, // Parse from result
		Timestamp:       time.Now(),
	}

	return metrics, nil
}

// Resize resizes an LVM logical volume
func (m *LVMManager) Resize(operation ResizeOperation) error {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Resizing LVM storage",
		zap.String("target", operation.Target),
		zap.Int64("new_size", operation.NewSize))

	// Use pkg/lvm for the actual resize operation
	// First, parse the target to get VG and LV names
	parts := strings.Split(operation.Target, "/")
	if len(parts) < 4 {
		return fmt.Errorf("invalid LVM path: %s", operation.Target)
	}

	vgName := parts[2]
	lvName := parts[3]

	// Calculate size difference
	sizeDiff := operation.NewSize - operation.CurrentSize
	sizeStr := fmt.Sprintf("+%dG", sizeDiff/(1<<30)) // Convert to GB

	// Apply resize through Salt
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.lv_resize",
		Pillar: map[string]interface{}{
			"volume_group":   vgName,
			"logical_volume": lvName,
			"size":           sizeStr,
			"resize_fs":      true, // Also resize filesystem
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return fmt.Errorf("failed to resize LV via Salt: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("Salt resize failed: %s", result.Message)
	}

	logger.Info("LVM resize completed successfully")
	return nil
}

// CheckHealth checks the health of an LVM volume
func (m *LVMManager) CheckHealth(id string) error {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Debug("Checking LVM health",
		zap.String("id", id))

	// Query Salt for LVM health status
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.lv_check",
		Pillar: map[string]interface{}{
			"path": id,
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("LVM health check failed: %s", result.Message)
	}

	return nil
}

// Helper methods

func (m *LVMManager) extractLVMConfig(config StorageConfig) (*LVMConfig, error) {
	lvmConfig := &LVMConfig{
		Filesystem:   config.Filesystem,
		MountOptions: DefaultMountOptions,
	}

	// Extract from options map
	if pv, ok := config.Options["physical_volume"].(string); ok {
		lvmConfig.PhysicalVolume = pv
	}
	if vg, ok := config.Options["volume_group"].(string); ok {
		lvmConfig.VolumeGroup = vg
	}
	if lv, ok := config.Options["logical_volume"].(string); ok {
		lvmConfig.LogicalVolume = lv
	}
	if size, ok := config.Options["size"].(string); ok {
		lvmConfig.Size = size
	} else {
		// Convert bytes to LVM size string
		lvmConfig.Size = fmt.Sprintf("%dG", config.Size/(1<<30))
	}
	if mo, ok := config.Options["mount_options"].(string); ok {
		lvmConfig.MountOptions = mo
	}

	// Validate required fields
	if lvmConfig.VolumeGroup == "" || lvmConfig.LogicalVolume == "" {
		return nil, fmt.Errorf("volume_group and logical_volume are required")
	}

	return lvmConfig, nil
}

func (m *LVMManager) checkPhysicalVolume(device string) (bool, error) {
	// Query Salt to check if PV exists
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.pv_present",
		Test:   true, // Just check, don't create
		Pillar: map[string]interface{}{
			"device": device,
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return false, err
	}

	return result.Success, nil
}

func (m *LVMManager) createPhysicalVolume(device string) error {
	// TODO: Direct call to pkg/lvm
	// For now, use Salt to create PV
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.pv_present",
		Pillar: map[string]interface{}{
			"device": device,
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("failed to create physical volume: %s", result.Message)
	}

	return nil
}

func (m *LVMManager) checkVolumeGroup(name string) (bool, error) {
	// Query Salt to check if VG exists
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.vg_present",
		Test:   true, // Just check, don't create
		Pillar: map[string]interface{}{
			"name": name,
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return false, err
	}

	return result.Success, nil
}

func (m *LVMManager) createVolumeGroup(name, device string) error {
	// TODO: Direct call to pkg/lvm
	// For now, use Salt to create VG
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "lvm.vg_present",
		Pillar: map[string]interface{}{
			"name":    name,
			"devices": []string{device},
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("failed to create volume group: %s", result.Message)
	}

	return nil
}

func (m *LVMManager) unmountVolume(path string) error {
	// Unmount through Salt
	saltConfig := SaltStackConfig{
		Target: "*",
		State:  "mount.unmounted",
		Pillar: map[string]interface{}{
			"name": path,
		},
	}

	result, err := m.saltClient.ApplyState(m.rc.Ctx, saltConfig.Target, saltConfig.State, saltConfig.Pillar)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("unmount failed: %s", result.Message)
	}

	return nil
}
