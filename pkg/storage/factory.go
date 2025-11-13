package storage

import (
	"context"
	"fmt"
	"sync"

	// disk_management functionality now consolidated into storage package
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/zfs_management"
	"github.com/hashicorp/nomad/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DriverRegistry manages storage driver registration and creation
type DriverRegistry struct {
	mu      sync.RWMutex
	drivers map[StorageType]StorageDriverFactory
	rc      *eos_io.RuntimeContext
}

// ZFSDriverFactory creates ZFS storage drivers
type ZFSDriverFactory struct{}

// CephFSDriverFactory creates CephFS storage drivers
type CephFSDriverFactory struct{}

// NewDriverRegistry creates a new driver registry
func NewDriverRegistry(rc *eos_io.RuntimeContext, nomadClient *api.Client) *DriverRegistry {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating storage driver registry")

	registry := &DriverRegistry{
		drivers: make(map[StorageType]StorageDriverFactory),
		rc:      rc,
	}

	// Register default drivers
	registry.registerDefaultDrivers()

	return registry
}

// Register registers a storage driver factory
func (r *DriverRegistry) Register(storageType StorageType, factory StorageDriverFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.drivers[storageType]; exists {
		return fmt.Errorf("driver already registered for type: %s", storageType)
	}

	r.drivers[storageType] = factory
	return nil
}

// CreateDriver creates a storage driver for the given type
func (r *DriverRegistry) CreateDriver(storageType StorageType, config DriverConfig) (StorageDriver, error) {
	r.mu.RLock()
	factory, exists := r.drivers[storageType]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no driver registered for type: %s", storageType)
	}

	return factory.CreateDriver(r.rc, config)
}

// GetSupportedTypes returns all supported storage types
func (r *DriverRegistry) GetSupportedTypes() []StorageType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]StorageType, 0, len(r.drivers))
	for t := range r.drivers {
		types = append(types, t)
	}
	return types
}

// registerDefaultDrivers registers the built-in storage drivers
func (r *DriverRegistry) registerDefaultDrivers() {
	logger := otelzap.Ctx(r.rc.Ctx)
	logger.Info("Registering default storage drivers")

	// Register Docker Volume driver
	_ = r.Register(StorageType("docker"), &DockerVolumeDriverFactory{})
}

// LVMDriverFactory creates LVM storage drivers
type LVMDriverFactory struct {
}

// CreateDriver creates an LVM storage driver
func (f *LVMDriverFactory) CreateDriver(rc *eos_io.RuntimeContext, config DriverConfig) (StorageDriver, error) {
	// Use existing LVM package functionality
	return &LVMDriver{
		rc: rc,
	}, nil
}

// SupportsType checks if this factory supports the given type
func (f *LVMDriverFactory) SupportsType(storageType StorageType) bool {
	return storageType == StorageTypeLVM
}

// BTRFSDriverFactory creates BTRFS storage drivers
type BTRFSDriverFactory struct {
}

// CreateDriver creates a BTRFS storage driver
func (f *BTRFSDriverFactory) CreateDriver(rc *eos_io.RuntimeContext, config DriverConfig) (StorageDriver, error) {
	// The BTRFSDriver uses NomadClient for orchestration
	// Storage operations are handled through Nomad job scheduling
	return &BTRFSDriver{
		rc: rc,
	}, nil
}

// SupportsType checks if this factory supports the given type
func (f *BTRFSDriverFactory) SupportsType(storageType StorageType) bool {
	return storageType == StorageTypeBTRFS
}

// CreateDriver creates a ZFS storage driver
func (f *ZFSDriverFactory) CreateDriver(rc *eos_io.RuntimeContext, config DriverConfig) (StorageDriver, error) {
	// Use existing ZFS management package
	manager := zfs_management.NewZFSManager(nil)

	return &ZFSDriver{
		rc:      rc,
		manager: manager,
	}, nil
}

// SupportsType checks if this factory supports the given type
func (f *ZFSDriverFactory) SupportsType(storageType StorageType) bool {
	return storageType == StorageTypeZFS
}

// CreateDriver creates a CephFS storage driver
func (f *CephFSDriverFactory) CreateDriver(rc *eos_io.RuntimeContext, config DriverConfig) (StorageDriver, error) {
	// The CephFSDriver uses NomadClient for distributed storage orchestration
	// CephFS operations are handled through Nomad job scheduling
	return &CephFSDriver{
		rc: rc,
	}, nil
}

// SupportsType checks if this factory supports the given type
func (f *CephFSDriverFactory) SupportsType(storageType StorageType) bool {
	return storageType == StorageTypeCephFS
}

// DockerVolumeDriverFactory creates Docker volume drivers
type DockerVolumeDriverFactory struct{}

// CreateDriver creates a Docker volume driver
func (f *DockerVolumeDriverFactory) CreateDriver(rc *eos_io.RuntimeContext, config DriverConfig) (StorageDriver, error) {
	return &DockerVolumeDriver{
		rc: rc,
	}, nil
}

// SupportsType checks if this factory supports the given type
func (f *DockerVolumeDriverFactory) SupportsType(storageType StorageType) bool {
	return storageType == StorageType("docker")
}

// UnifiedStorageManager provides high-level storage management
// by coordinating between different storage drivers
type UnifiedStorageManager struct {
	rc          *eos_io.RuntimeContext
	registry    *DriverRegistry
	diskManager *DiskManagerImpl
	drivers     map[StorageType]StorageDriver
	_           sync.RWMutex
}

// NewUnifiedStorageManager creates a new unified storage manager
func NewUnifiedStorageManager(rc *eos_io.RuntimeContext, nomadClient *api.Client) (*UnifiedStorageManager, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating unified storage manager")

	diskManager := NewDiskManagerImpl(nil)
	registry := NewDriverRegistry(rc, nomadClient)

	manager := &UnifiedStorageManager{
		rc:          rc,
		registry:    registry,
		diskManager: diskManager,
		drivers:     make(map[StorageType]StorageDriver),
	}

	// Initialize drivers for all supported types
	if err := manager.initializeDrivers(); err != nil {
		return nil, fmt.Errorf("failed to initialize drivers: %w", err)
	}

	return manager, nil
}

// initializeDrivers initializes all available storage drivers
func (m *UnifiedStorageManager) initializeDrivers() error {
	logger := otelzap.Ctx(m.rc.Ctx)

	for _, storageType := range m.registry.GetSupportedTypes() {
		logger.Info("Initializing storage driver",
			zap.String("type", string(storageType)))

		driver, err := m.registry.CreateDriver(storageType, nil)
		if err != nil {
			logger.Warn("Failed to initialize driver",
				zap.String("type", string(storageType)),
				zap.Error(err))
			continue
		}

		m.drivers[storageType] = driver
	}

	if len(m.drivers) == 0 {
		return fmt.Errorf("no storage drivers could be initialized")
	}

	return nil
}

// CreateVolume creates a new volume with optimal settings for the workload
func (m *UnifiedStorageManager) CreateVolume(ctx context.Context, name string, config VolumeConfig) (*VolumeInfo, error) {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Creating volume",
		zap.String("name", name),
		zap.String("type", string(config.Type)),
		zap.String("workload", config.Workload))

	// ASSESS - Validate configuration and select optimal storage type
	storageType := m.selectOptimalStorageType(config)

	driver, exists := m.drivers[storageType]
	if !exists {
		return nil, fmt.Errorf("no driver available for storage type: %s", storageType)
	}

	// Convert VolumeConfig to StorageConfig for the driver
	storageConfig := m.volumeConfigToStorageConfig(config)

	// INTERVENE - Create the volume
	if err := driver.Create(ctx, storageConfig); err != nil {
		return nil, fmt.Errorf("failed to create volume: %w", err)
	}

	// EVALUATE - Get the created volume information
	info, err := driver.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to verify volume creation: %w", err)
	}

	// Convert StorageInfo to VolumeInfo
	volumeInfo := m.storageInfoToVolumeInfo(info)

	logger.Info("Volume created successfully",
		zap.String("id", volumeInfo.ID),
		zap.String("type", string(volumeInfo.Type)))

	return volumeInfo, nil
}

// GetVolume retrieves volume information
func (m *UnifiedStorageManager) GetVolume(ctx context.Context, id string) (*VolumeInfo, error) {
	// Try each driver until we find the volume
	for _, driver := range m.drivers {
		info, err := driver.Get(ctx, id)
		if err == nil {
			return m.storageInfoToVolumeInfo(info), nil
		}
	}

	return nil, fmt.Errorf("volume not found: %s", id)
}

// ListVolumes lists all volumes, optionally filtered
func (m *UnifiedStorageManager) ListVolumes(ctx context.Context, filter VolumeFilter) ([]*VolumeInfo, error) {
	logger := otelzap.Ctx(m.rc.Ctx)
	logger.Info("Listing volumes")

	var allVolumes []*VolumeInfo

	// If specific types are requested, only query those drivers
	driversToQuery := m.drivers
	if len(filter.Types) > 0 {
		driversToQuery = make(map[StorageType]StorageDriver)
		for _, t := range filter.Types {
			if driver, exists := m.drivers[t]; exists {
				driversToQuery[t] = driver
			}
		}
	}

	// Query each driver
	for storageType, driver := range driversToQuery {
		logger.Debug("Querying driver for volumes",
			zap.String("type", string(storageType)))

		infos, err := driver.List(ctx)
		if err != nil {
			logger.Warn("Failed to list volumes from driver",
				zap.String("type", string(storageType)),
				zap.Error(err))
			continue
		}

		// Convert and filter
		for _, info := range infos {
			volumeInfo := m.storageInfoToVolumeInfo(&info)
			if m.matchesFilter(volumeInfo, filter) {
				allVolumes = append(allVolumes, volumeInfo)
			}
		}
	}

	return allVolumes, nil
}

// Helper methods

// selectOptimalStorageType selects the best storage type for a workload
func (m *UnifiedStorageManager) selectOptimalStorageType(config VolumeConfig) StorageType {
	// If type is explicitly specified, use it
	if config.Type != "" {
		return config.Type
	}

	// Select based on workload
	switch config.Workload {
	case "database":
		// XFS on LVM for databases
		return StorageTypeLVM

	case "backup":
		// BTRFS for compression and deduplication
		return StorageTypeBTRFS

	case "distributed":
		// CephFS for distributed workloads
		return StorageTypeCephFS

	case "container":
		// Docker volumes for containers
		return StorageType("docker")

	default:
		// Default to LVM
		return StorageTypeLVM
	}
}

// volumeConfigToStorageConfig converts VolumeConfig to StorageConfig
func (m *UnifiedStorageManager) volumeConfigToStorageConfig(vc VolumeConfig) StorageConfig {
	return StorageConfig{
		Type:       vc.Type,
		Filesystem: vc.Filesystem,
		MountPoint: vc.MountPoint,
		Size:       vc.Size,
		Options:    vc.DriverConfig,
	}
}

// storageInfoToVolumeInfo converts StorageInfo to VolumeInfo
func (m *UnifiedStorageManager) storageInfoToVolumeInfo(si *StorageInfo) *VolumeInfo {
	return &VolumeInfo{
		StorageInfo: *si,
	}
}

// matchesFilter checks if a volume matches the filter criteria
func (m *UnifiedStorageManager) matchesFilter(vi *VolumeInfo, filter VolumeFilter) bool {
	// Check state filter
	if len(filter.States) > 0 {
		found := false
		for _, state := range filter.States {
			if vi.State == state {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check size filters
	if filter.MinSize != nil && vi.TotalSize < *filter.MinSize {
		return false
	}
	if filter.MaxSize != nil && vi.TotalSize > *filter.MaxSize {
		return false
	}

	// Check mount point
	if filter.MountPoint != nil && vi.MountPoint != *filter.MountPoint {
		return false
	}

	// Check labels
	if len(filter.Labels) > 0 {
		// This would check if volume has any of the specified labels
		// For now, return true
	}

	return true
}

// GetOptimalStorageForWorkload returns the optimal storage configuration for a workload
func GetOptimalStorageForWorkload(workload string) VolumeConfig {
	switch workload {
	case "database":
		return VolumeConfig{
			Type:         StorageTypeLVM,
			Filesystem:   FilesystemXFS,
			MountOptions: []string{"noatime", "nodiratime", "nobarrier"},
			Workload:     workload,
		}

	case "backup":
		return VolumeConfig{
			Type:         StorageTypeBTRFS,
			Filesystem:   FilesystemBTRFS,
			MountOptions: []string{"compress=zstd:3", "noatime", "space_cache=v2"},
			Workload:     workload,
			DriverConfig: map[string]interface{}{
				"compression":       "zstd",
				"compression_level": 3,
			},
		}

	case "container":
		return VolumeConfig{
			Type:         StorageTypeLVM,
			Filesystem:   FilesystemExt4,
			MountOptions: []string{"defaults", "noatime"},
			Workload:     workload,
		}

	case "media":
		return VolumeConfig{
			Type:         StorageTypeBTRFS,
			Filesystem:   FilesystemBTRFS,
			MountOptions: []string{"compress=zstd:1", "noatime"},
			Workload:     workload,
		}

	case "distributed":
		return VolumeConfig{
			Type:       StorageTypeCephFS,
			Filesystem: FilesystemType("cephfs"),
			Workload:   workload,
		}

	default:
		// General purpose
		return VolumeConfig{
			Type:         StorageTypeLVM,
			Filesystem:   FilesystemExt4,
			MountOptions: []string{"defaults", "noatime"},
			Workload:     "general",
		}
	}
}
