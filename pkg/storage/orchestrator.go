package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Orchestrator coordinates storage operations across different backends
// following the Eos infrastructure compiler pattern:
// Human Intent → Eos CLI → SaltStack → Storage Backend
type Orchestrator struct {
	rc         *eos_io.RuntimeContext
	saltClient NomadClient
	managers   map[StorageType]StorageManager
}

// NewOrchestrator creates a new storage orchestrator
func NewOrchestrator(rc *eos_io.RuntimeContext, saltClient NomadClient) (*Orchestrator, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating storage orchestrator")

	o := &Orchestrator{
		rc:         rc,
		saltClient: saltClient,
		managers:   make(map[StorageType]StorageManager),
	}

	// Initialize storage managers for each backend type
	if err := o.initializeManagers(); err != nil {
		return nil, fmt.Errorf("failed to initialize storage managers: %w", err)
	}

	return o, nil
}

// initializeManagers sets up the storage managers for each backend
func (o *Orchestrator) initializeManagers() error {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Initializing storage managers")

	// Initialize LVM manager
	lvmManager, err := NewLVMManager(o.rc, o.saltClient)
	if err != nil {
		logger.Warn("Failed to initialize LVM manager", zap.Error(err))
	} else {
		o.managers[StorageTypeLVM] = lvmManager
	}

	// TODO: Initialize BTRFS manager
	// btrfsManager, err := NewBTRFSManager(o.rc, o.saltClient)
	// if err != nil {
	// 	logger.Warn("Failed to initialize BTRFS manager", zap.Error(err))
	// } else {
	// 	o.managers[StorageTypeBTRFS] = btrfsManager
	// }

	// TODO: Initialize CephFS manager
	// cephfsManager, err := NewCephFSManager(o.rc, o.saltClient)
	// if err != nil {
	// 	logger.Warn("Failed to initialize CephFS manager", zap.Error(err))
	// } else {
	// 	o.managers[StorageTypeCephFS] = cephfsManager
	// }

	// TODO: Initialize ZFS manager
	// zfsManager, err := NewZFSManager(o.rc, o.saltClient)
	// if err != nil {
	// 	logger.Warn("Failed to initialize ZFS manager", zap.Error(err))
	// } else {
	// 	o.managers[StorageTypeZFS] = zfsManager
	// }

	if len(o.managers) == 0 {
		return fmt.Errorf("no storage managers could be initialized")
	}

	logger.Info("Storage managers initialized",
		zap.Int("count", len(o.managers)))

	return nil
}

// CreateStorage creates a new storage resource through Salt
func (o *Orchestrator) CreateStorage(config StorageConfig) error {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Creating storage resource",
		zap.String("type", string(config.Type)),
		zap.String("device", config.Device))

	// ASSESS - Check prerequisites
	if err := o.assessCreatePrerequisites(config); err != nil {
		return fmt.Errorf("prerequisites not met: %w", err)
	}

	// Get appropriate manager
	manager, ok := o.managers[config.Type]
	if !ok {
		return fmt.Errorf("no manager available for storage type: %s", config.Type)
	}

	// INTERVENE - Create through manager (which uses Salt)
	if err := manager.Create(config); err != nil {
		return fmt.Errorf("failed to create storage: %w", err)
	}

	// EVALUATE - Verify creation succeeded
	status, err := manager.Read(config.Device)
	if err != nil {
		return fmt.Errorf("failed to verify storage creation: %w", err)
	}

	if status.State != "active" {
		return fmt.Errorf("storage created but not active: %s", status.State)
	}

	logger.Info("Storage resource created successfully",
		zap.String("device", config.Device),
		zap.String("state", status.State))

	return nil
}

// ReadStorage gets information about a storage resource
func (o *Orchestrator) ReadStorage(storageType StorageType, id string) (*StorageStatus, error) {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Reading storage resource",
		zap.String("type", string(storageType)),
		zap.String("id", id))

	manager, ok := o.managers[storageType]
	if !ok {
		return nil, fmt.Errorf("no manager available for storage type: %s", storageType)
	}

	return manager.Read(id)
}

// ListStorage lists all storage resources of a given type
func (o *Orchestrator) ListStorage(storageType StorageType) ([]*StorageStatus, error) {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Listing storage resources",
		zap.String("type", string(storageType)))

	if storageType == "" {
		// List all storage across all managers
		var allStorage []*StorageStatus
		for sType, manager := range o.managers {
			logger.Debug("Listing storage for type", zap.String("type", string(sType)))
			resources, err := manager.List()
			if err != nil {
				logger.Warn("Failed to list storage",
					zap.String("type", string(sType)),
					zap.Error(err))
				continue
			}
			allStorage = append(allStorage, resources...)
		}
		return allStorage, nil
	}

	manager, ok := o.managers[storageType]
	if !ok {
		return nil, fmt.Errorf("no manager available for storage type: %s", storageType)
	}

	return manager.List()
}

// UpdateStorage updates a storage resource configuration
func (o *Orchestrator) UpdateStorage(storageType StorageType, id string, config StorageConfig) error {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Updating storage resource",
		zap.String("type", string(storageType)),
		zap.String("id", id))

	// ASSESS - Check current state
	manager, ok := o.managers[storageType]
	if !ok {
		return fmt.Errorf("no manager available for storage type: %s", storageType)
	}

	currentStatus, err := manager.Read(id)
	if err != nil {
		return fmt.Errorf("failed to read current state: %w", err)
	}

	// INTERVENE - Apply update
	if err := manager.Update(id, config); err != nil {
		return fmt.Errorf("failed to update storage: %w", err)
	}

	// EVALUATE - Verify update succeeded
	newStatus, err := manager.Read(id)
	if err != nil {
		return fmt.Errorf("failed to verify storage update: %w", err)
	}

	logger.Info("Storage resource updated successfully",
		zap.String("id", id),
		zap.String("previous_state", currentStatus.State),
		zap.String("new_state", newStatus.State))

	return nil
}

// DeleteStorage removes a storage resource
func (o *Orchestrator) DeleteStorage(storageType StorageType, id string) error {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Deleting storage resource",
		zap.String("type", string(storageType)),
		zap.String("id", id))

	// ASSESS - Check if safe to delete
	manager, ok := o.managers[storageType]
	if !ok {
		return fmt.Errorf("no manager available for storage type: %s", storageType)
	}

	status, err := manager.Read(id)
	if err != nil {
		return fmt.Errorf("failed to read storage state: %w", err)
	}

	if status.Mounted {
		return fmt.Errorf("cannot delete mounted storage: %s", status.MountPoint)
	}

	// INTERVENE - Delete the resource
	if err := manager.Delete(id); err != nil {
		return fmt.Errorf("failed to delete storage: %w", err)
	}

	// EVALUATE - Verify deletion
	_, err = manager.Read(id)
	if err == nil {
		return fmt.Errorf("storage deletion failed: resource still exists")
	}

	logger.Info("Storage resource deleted successfully", zap.String("id", id))
	return nil
}

// ResizeStorage resizes a storage resource
func (o *Orchestrator) ResizeStorage(operation ResizeOperation) error {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Resizing storage resource",
		zap.String("target", operation.Target),
		zap.Int64("current_size", operation.CurrentSize),
		zap.Int64("new_size", operation.NewSize))

	// Determine storage type from target
	storageType, err := o.detectStorageType(operation.Target)
	if err != nil {
		return fmt.Errorf("failed to detect storage type: %w", err)
	}

	manager, ok := o.managers[storageType]
	if !ok {
		return fmt.Errorf("no manager available for storage type: %s", storageType)
	}

	// ASSESS - Check if resize is possible
	if operation.NewSize < operation.CurrentSize && operation.Type != "shrink" {
		return fmt.Errorf("shrinking requires explicit type=shrink")
	}

	// INTERVENE - Perform resize
	if err := manager.Resize(operation); err != nil {
		return fmt.Errorf("failed to resize storage: %w", err)
	}

	// EVALUATE - Verify new size
	status, err := manager.Read(operation.Target)
	if err != nil {
		return fmt.Errorf("failed to verify resize: %w", err)
	}

	if status.TotalSize < operation.NewSize {
		return fmt.Errorf("resize failed: expected %d, got %d", operation.NewSize, status.TotalSize)
	}

	logger.Info("Storage resized successfully",
		zap.String("target", operation.Target),
		zap.Int64("new_size", status.TotalSize))

	return nil
}

// GetMetrics retrieves performance metrics for a storage resource
func (o *Orchestrator) GetMetrics(storageType StorageType, id string) (*StorageMetrics, error) {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Debug("Getting storage metrics",
		zap.String("type", string(storageType)),
		zap.String("id", id))

	manager, ok := o.managers[storageType]
	if !ok {
		return nil, fmt.Errorf("no manager available for storage type: %s", storageType)
	}

	return manager.GetMetrics(id)
}

// CheckHealth performs health check on storage resources
func (o *Orchestrator) CheckHealth(ctx context.Context) ([]StorageAlert, error) {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Checking storage health")

	var alerts []StorageAlert

	for storageType, manager := range o.managers {
		logger.Debug("Checking health for storage type", zap.String("type", string(storageType)))

		resources, err := manager.List()
		if err != nil {
			logger.Warn("Failed to list resources for health check",
				zap.String("type", string(storageType)),
				zap.Error(err))
			continue
		}

		for _, resource := range resources {
			if err := manager.CheckHealth(resource.ID); err != nil {
				alert := StorageAlert{
					ID:           fmt.Sprintf("%s-%s-health", storageType, resource.ID),
					Severity:     "warning",
					Type:         "health_check_failed",
					Resource:     resource.ID,
					Message:      err.Error(),
					CurrentValue: float64(resource.UsagePercent),
					Timestamp:    time.Now(),
				}
				alerts = append(alerts, alert)
			}

			// Check usage thresholds
			if resource.UsagePercent > CriticalThreshold {
				alert := StorageAlert{
					ID:           fmt.Sprintf("%s-%s-critical", storageType, resource.ID),
					Severity:     "critical",
					Type:         "usage_critical",
					Resource:     resource.ID,
					Message:      fmt.Sprintf("Storage usage critical: %.1f%%", resource.UsagePercent),
					Threshold:    CriticalThreshold,
					CurrentValue: resource.UsagePercent,
					Timestamp:    time.Now(),
				}
				alerts = append(alerts, alert)
			} else if resource.UsagePercent > WarningThreshold {
				alert := StorageAlert{
					ID:           fmt.Sprintf("%s-%s-warning", storageType, resource.ID),
					Severity:     "warning",
					Type:         "usage_warning",
					Resource:     resource.ID,
					Message:      fmt.Sprintf("Storage usage warning: %.1f%%", resource.UsagePercent),
					Threshold:    WarningThreshold,
					CurrentValue: resource.UsagePercent,
					Timestamp:    time.Now(),
				}
				alerts = append(alerts, alert)
			}
		}
	}

	logger.Info("Storage health check completed",
		zap.Int("alerts", len(alerts)))

	return alerts, nil
}

// AutoResize handles automatic storage expansion based on usage
func (o *Orchestrator) AutoResize(ctx context.Context, threshold float64) error {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Running auto-resize check",
		zap.Float64("threshold", threshold))

	for storageType, manager := range o.managers {
		resources, err := manager.List()
		if err != nil {
			logger.Warn("Failed to list resources for auto-resize",
				zap.String("type", string(storageType)),
				zap.Error(err))
			continue
		}

		for _, resource := range resources {
			if resource.UsagePercent > threshold {
				logger.Info("Storage exceeds threshold, considering resize",
					zap.String("resource", resource.ID),
					zap.Float64("usage", resource.UsagePercent))

				// Calculate new size (increase by 50%)
				newSize := int64(float64(resource.TotalSize) * 1.5)

				operation := ResizeOperation{
					Target:      resource.ID,
					CurrentSize: resource.TotalSize,
					NewSize:     newSize,
					Type:        "grow",
				}

				if err := manager.Resize(operation); err != nil {
					logger.Error("Auto-resize failed",
						zap.String("resource", resource.ID),
						zap.Error(err))
				} else {
					logger.Info("Auto-resize completed",
						zap.String("resource", resource.ID),
						zap.Int64("new_size", newSize))
				}
			}
		}
	}

	return nil
}

// assessCreatePrerequisites checks if storage creation is possible
func (o *Orchestrator) assessCreatePrerequisites(config StorageConfig) error {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Assessing storage creation prerequisites")

	// Validate configuration
	if config.Device == "" {
		return fmt.Errorf("device path is required")
	}

	if config.Size < MinVolumeSize {
		return fmt.Errorf("size must be at least %d bytes", MinVolumeSize)
	}

	if config.Size > MaxVolumeSize {
		return fmt.Errorf("size cannot exceed %d bytes", MaxVolumeSize)
	}

	// Check if manager exists for the storage type
	if _, ok := o.managers[config.Type]; !ok {
		return fmt.Errorf("no manager available for storage type: %s", config.Type)
	}

	return nil
}

// detectStorageType attempts to detect the storage type from a device path
func (o *Orchestrator) detectStorageType(device string) (StorageType, error) {
	// This is a simplified detection logic
	// In production, this would query Salt to determine the actual type

	// Check through each manager to see if it recognizes the device
	for storageType, manager := range o.managers {
		if _, err := manager.Read(device); err == nil {
			return storageType, nil
		}
	}

	return "", fmt.Errorf("unable to detect storage type for device: %s", device)
}

// CreateOptimalStorage creates storage with optimal settings based on workload
func (o *Orchestrator) CreateOptimalStorage(workload string, size int64, location string) error {
	logger := otelzap.Ctx(o.rc.Ctx)
	logger.Info("Creating optimal storage for workload",
		zap.String("workload", workload),
		zap.Int64("size", size))

	var config StorageConfig

	switch workload {
	case "database":
		// XFS on LVM for databases (best random I/O)
		config = StorageConfig{
			Type:       StorageTypeLVM,
			Filesystem: FilesystemXFS,
			Size:       size,
			MountPoint: location,
			Options: map[string]interface{}{
				"mount_options": "noatime,nodiratime,nobarrier",
			},
		}

	case "backup":
		// BTRFS for backups (compression and deduplication)
		config = StorageConfig{
			Type:       StorageTypeBTRFS,
			Filesystem: FilesystemBTRFS,
			Size:       size,
			MountPoint: location,
			Options: map[string]interface{}{
				"compression":       "zstd",
				"compression_level": 3,
				"mount_options":     "compress=zstd:3,noatime,space_cache=v2",
			},
		}

	case "container":
		// ext4 for container runtime (simplicity)
		config = StorageConfig{
			Type:       StorageTypeLVM,
			Filesystem: FilesystemExt4,
			Size:       size,
			MountPoint: location,
			Options: map[string]interface{}{
				"mount_options": DefaultMountOptions,
			},
		}

	case "distributed":
		// CephFS for distributed storage
		config = StorageConfig{
			Type:       StorageTypeCephFS,
			Filesystem: FilesystemType("cephfs"),
			Size:       size,
			MountPoint: location,
			Options:    map[string]interface{}{},
		}

	default:
		// Default to ext4 on LVM
		config = StorageConfig{
			Type:       StorageTypeLVM,
			Filesystem: FilesystemExt4,
			Size:       size,
			MountPoint: location,
			Options: map[string]interface{}{
				"mount_options": DefaultMountOptions,
			},
		}
	}

	return o.CreateStorage(config)
}
