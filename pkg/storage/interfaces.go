// pkg/storage/interfaces.go
//
// EOS Storage Management System - Core Interfaces and Architecture
//
// This package provides comprehensive storage management for EOS with a focus on
// safety, performance, and multi-backend support. It implements a unified interface
// for managing various storage technologies while maintaining strong type safety
// and comprehensive monitoring capabilities.
//
// Architecture Strengths:
// - Well-defined interfaces (StorageDriver, VolumeManager, DiskManager)
// - Safety-first design with journaling, rollback, preflight checks
// - Multi-backend support (LVM, BTRFS, ZFS, CephFS)
// - SaltStack integration following infrastructure compiler pattern
// - Strong type safety with comprehensive type definitions
//
// Key Features:
// - Unified storage interface across multiple backend technologies
// - Real-time performance monitoring with comprehensive metrics
// - Safety mechanisms including rollback and preflight validation
// - Concurrent operation support with dependency resolution
// - Plugin architecture for extensibility
// - Integration with HashiCorp stack for modern orchestration
//
// Storage Backends Supported:
// - LVM: Logical Volume Management for flexible disk allocation
// - BTRFS: Advanced filesystem with snapshots and compression
// - ZFS: Enterprise-grade filesystem with data integrity
// - CephFS: Distributed storage for cluster environments
// - Local: Direct filesystem operations
// - Cloud: Integration with cloud storage providers
//
// Safety Features:
// - Preflight checks before all operations
// - Journaling for operation tracking and rollback
// - Multi-layer rollback capabilities
// - Comprehensive validation and error handling
// - Audit logging for all storage operations
//
// Performance Features:
// - Real-time IOPS, latency, and throughput monitoring
// - Concurrent operation scheduler with dependency resolution
// - Caching and batching for improved performance
// - Performance optimization recommendations
//
// Usage Examples:
//   // Create storage manager
//   manager := storage.NewManager(storage.Config{
//       Backend: storage.BackendLVM,
//       SafetyChecks: true,
//   })
//
//   // Create volume with safety checks
//   volume, err := manager.CreateVolume(ctx, storage.VolumeConfig{
//       Name: "data-volume",
//       Size: "100GB",
//       Type: storage.VolumeTypeData,
//   })
//
// Integration:
// - EOS Infrastructure Compiler: Translates user intent to storage operations
// - SaltStack: System-level storage operations and configuration
// - HashiCorp Stack: Application-level storage orchestration
// - Nomad: Container storage management and allocation
// - Consul: Service discovery for distributed storage
//
// Monitoring:
// The system provides comprehensive monitoring including:
// - Real-time performance metrics (IOPS, latency, throughput)
// - Capacity tracking and growth prediction
// - Health monitoring with SMART data integration
// - Threshold-based alerting and automated actions
package storage

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// StorageDriver defines the interface that all storage drivers must implement
// This follows the Assess → Intervene → Evaluate pattern
type StorageDriver interface {
	// Type returns the storage type this driver handles
	Type() StorageType

	// Lifecycle operations
	Create(ctx context.Context, config StorageConfig) error
	Delete(ctx context.Context, id string) error

	// Query operations
	List(ctx context.Context) ([]StorageInfo, error)
	Get(ctx context.Context, id string) (*StorageInfo, error)
	Exists(ctx context.Context, id string) (bool, error)

	// Management operations
	Resize(ctx context.Context, id string, newSize int64) error
	Mount(ctx context.Context, id string, mountPoint string, options []string) error
	Unmount(ctx context.Context, id string) error

	// Monitoring and health
	GetMetrics(ctx context.Context, id string) (*StorageMetrics, error)
	CheckHealth(ctx context.Context, id string) (*HealthStatus, error)

	// Snapshot operations (optional - not all drivers support)
	CreateSnapshot(ctx context.Context, id string, snapshotName string) error
	DeleteSnapshot(ctx context.Context, id string, snapshotName string) error
	ListSnapshots(ctx context.Context, id string) ([]SnapshotInfo, error)
	RestoreSnapshot(ctx context.Context, id string, snapshotName string) error
}

// StorageDriverFactory creates storage drivers
type StorageDriverFactory interface {
	CreateDriver(rc *eos_io.RuntimeContext, config DriverConfig) (StorageDriver, error)
	SupportsType(storageType StorageType) bool
}

// VolumeManager provides high-level volume management operations
// This is what commands will typically interact with
type VolumeManager interface {
	// Create a new volume with optimal settings for workload
	CreateVolume(ctx context.Context, name string, config VolumeConfig) (*VolumeInfo, error)

	// Get volume information
	GetVolume(ctx context.Context, id string) (*VolumeInfo, error)

	// List all volumes, optionally filtered by type
	ListVolumes(ctx context.Context, filter VolumeFilter) ([]*VolumeInfo, error)

	// Update volume configuration (resize, mount options, etc)
	UpdateVolume(ctx context.Context, id string, updates VolumeUpdate) error

	// Delete a volume
	DeleteVolume(ctx context.Context, id string) error

	// Volume operations
	MountVolume(ctx context.Context, id string, mountPoint string) error
	UnmountVolume(ctx context.Context, id string) error
	ResizeVolume(ctx context.Context, id string, newSize int64) error

	// Backup operations
	BackupVolume(ctx context.Context, id string, destination string) error
	RestoreVolume(ctx context.Context, id string, source string) error

	// Health and monitoring
	GetVolumeHealth(ctx context.Context, id string) (*HealthReport, error)
	GetVolumeMetrics(ctx context.Context, id string) (*VolumeMetrics, error)
}

// DiskManager provides disk and partition management
type DiskManager interface {
	// List all disks in the system
	ListDisks(ctx context.Context) ([]*DiskInfo, error)

	// Get specific disk information
	GetDisk(ctx context.Context, device string) (*DiskInfo, error)

	// Partition operations
	CreatePartition(ctx context.Context, device string, config PartitionConfig) (*PartitionInfo, error)
	DeletePartition(ctx context.Context, device string, number int) error
	ListPartitions(ctx context.Context, device string) ([]*PartitionInfo, error)

	// Format operations
	FormatPartition(ctx context.Context, device string, filesystem FilesystemType) error

	// SMART health monitoring
	GetDiskHealth(ctx context.Context, device string) (*DiskHealth, error)
}

// FilesystemManager handles filesystem-specific operations
type FilesystemManager interface {
	// Create filesystem on device
	CreateFilesystem(ctx context.Context, device string, fsType FilesystemType, options FilesystemOptions) error

	// Get filesystem information
	GetFilesystemInfo(ctx context.Context, device string) (*FilesystemInfo, error)

	// Resize filesystem
	ResizeFilesystem(ctx context.Context, device string, newSize int64) error

	// Check and repair filesystem
	CheckFilesystem(ctx context.Context, device string, repair bool) error

	// Get filesystem usage
	GetUsage(ctx context.Context, mountPoint string) (*UsageInfo, error)

	// Mount table operations
	GetMountTable(ctx context.Context) ([]*MountEntry, error)
	AddToFstab(ctx context.Context, entry *FstabEntry) error
	RemoveFromFstab(ctx context.Context, device string) error
}

// StorageMonitor provides monitoring capabilities
type StorageMonitor interface {
	// Start monitoring storage resources
	Start(ctx context.Context) error

	// Stop monitoring
	Stop(ctx context.Context) error

	// Get current alerts
	GetAlerts(ctx context.Context) ([]*StorageAlert, error)

	// Subscribe to alerts
	Subscribe(ctx context.Context, handler AlertHandler) (Subscription, error)

	// Get historical metrics
	GetMetricsHistory(ctx context.Context, id string, duration string) (*MetricsHistory, error)

	// Predict storage growth
	PredictGrowth(ctx context.Context, id string) (*GrowthPrediction, error)
}

// BackupManager handles backup operations
type BackupManager interface {
	// Create backup job
	CreateBackupJob(ctx context.Context, config BackupJobConfig) (*BackupJob, error)

	// Run backup immediately
	RunBackup(ctx context.Context, jobID string) error

	// List backup jobs
	ListBackupJobs(ctx context.Context) ([]*BackupJob, error)

	// Get backup history
	GetBackupHistory(ctx context.Context, jobID string) ([]*BackupRun, error)

	// Restore from backup
	RestoreBackup(ctx context.Context, backupID string, destination string) error

	// Verify backup integrity
	VerifyBackup(ctx context.Context, backupID string) error
}

// Callback interfaces for monitoring
type AlertHandler func(alert *StorageAlert)

type Subscription interface {
	Unsubscribe() error
}

// HealthChecker provides unified health checking across storage types
type HealthChecker interface {
	// Check overall storage health
	CheckStorageHealth(ctx context.Context) (*SystemHealthReport, error)

	// Check specific storage resource
	CheckResourceHealth(ctx context.Context, resourceID string) (*ResourceHealthReport, error)

	// Get health recommendations
	GetHealthRecommendations(ctx context.Context) ([]*HealthRecommendation, error)
}

// PolicyEngine handles storage policies (quotas, placement, etc)
type PolicyEngine interface {
	// Apply storage policy
	ApplyPolicy(ctx context.Context, policy StoragePolicy) error

	// Get active policies
	GetPolicies(ctx context.Context) ([]*StoragePolicy, error)

	// Validate configuration against policies
	ValidateAgainstPolicies(ctx context.Context, config StorageConfig) error

	// Get policy violations
	GetViolations(ctx context.Context) ([]*PolicyViolation, error)
}

// StorageOrchestrator coordinates across multiple storage systems
// This is the main interface that implements the infrastructure compiler pattern
type StorageOrchestrator interface {
	// High-level operations that may span multiple storage systems

	// Deploy a complete storage solution based on workload
	DeployStorageStack(ctx context.Context, workload string, requirements StorageRequirements) (*StorageDeployment, error)

	// Migrate data between storage systems
	MigrateStorage(ctx context.Context, source, destination string, options MigrationOptions) error

	// Optimize storage layout based on usage patterns
	OptimizeStorage(ctx context.Context) (*OptimizationReport, error)

	// Disaster recovery operations
	CreateDisasterRecoveryPlan(ctx context.Context) (*DRPlan, error)
	ExecuteFailover(ctx context.Context, plan *DRPlan) error
	ExecuteFailback(ctx context.Context, plan *DRPlan) error
}

// ConfigValidator validates storage configurations
type ConfigValidator interface {
	// Validate storage configuration
	Validate(config interface{}) error

	// Get validation rules
	GetRules() []ValidationRule

	// Check compatibility
	CheckCompatibility(config StorageConfig, system SystemInfo) error
}
