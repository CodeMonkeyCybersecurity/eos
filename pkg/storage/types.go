package storage

import (
	"time"

	"github.com/hashicorp/go-version"
)

// StorageType represents different storage backend types
type StorageType string

const (
	StorageTypeLVM    StorageType = "lvm"
	StorageTypeBTRFS  StorageType = "btrfs"
	StorageTypeZFS    StorageType = "zfs"
	StorageTypeCephFS StorageType = "cephfs"
	StorageTypeExt4   StorageType = "ext4"
	StorageTypeXFS    StorageType = "xfs"
)

// FilesystemType represents filesystem types
type FilesystemType string

const (
	FilesystemExt4  FilesystemType = "ext4"
	FilesystemXFS   FilesystemType = "xfs"
	FilesystemBTRFS FilesystemType = "btrfs"
	FilesystemZFS   FilesystemType = "zfs"
)

// StorageConfig holds configuration for storage operations
type StorageConfig struct {
	// Storage backend type
	Type StorageType `json:"type"`

	// Filesystem type
	Filesystem FilesystemType `json:"filesystem"`

	// Device path (e.g., /dev/sda, /dev/vg/lv)
	Device string `json:"device"`

	// Mount point
	MountPoint string `json:"mount_point"`

	// Size in bytes (for creation/resize)
	Size int64 `json:"size"`

	// Additional options specific to storage type
	Options map[string]interface{} `json:"options"`
}

// LVMConfig specific configuration for LVM operations
type LVMConfig struct {
	// Physical volume path
	PhysicalVolume string `json:"physical_volume"`

	// Volume group name
	VolumeGroup string `json:"volume_group"`

	// Logical volume name
	LogicalVolume string `json:"logical_volume"`

	// Size (supports units like "10G", "+5G", "100%FREE")
	Size string `json:"size"`

	// Filesystem type for the LV
	Filesystem FilesystemType `json:"filesystem"`

	// Mount options
	MountOptions string `json:"mount_options"`
}

// BTRFSConfig specific configuration for BTRFS operations
type BTRFSConfig struct {
	// Devices to use for BTRFS
	Devices []string `json:"devices"`

	// Compression algorithm (zstd, lzo, zlib)
	Compression string `json:"compression"`

	// Compression level (1-15 for zstd)
	CompressionLevel int `json:"compression_level"`

	// Enable deduplication
	Deduplication bool `json:"deduplication"`

	// Subvolume name
	Subvolume string `json:"subvolume"`

	// Mount options
	MountOptions string `json:"mount_options"`
}

// CephFSConfig specific configuration for CephFS operations
type CephFSConfig struct {
	// Ceph cluster name
	ClusterName string `json:"cluster_name"`

	// CephFS filesystem name
	FilesystemName string `json:"filesystem_name"`

	// Monitor addresses
	Monitors []string `json:"monitors"`

	// Client name for authentication
	ClientName string `json:"client_name"`

	// Mount path
	MountPath string `json:"mount_path"`

	// Pool names
	DataPool     string `json:"data_pool"`
	MetadataPool string `json:"metadata_pool"`
}

// ZFSConfig specific configuration for ZFS operations
type ZFSConfig struct {
	// Pool name
	PoolName string `json:"pool_name"`

	// Dataset name
	Dataset string `json:"dataset"`

	// RAID level (mirror, raidz, raidz2, raidz3)
	RaidLevel string `json:"raid_level"`

	// Devices for the pool
	Devices []string `json:"devices"`

	// Compression (lz4, gzip, zstd)
	Compression string `json:"compression"`

	// Mount point
	MountPoint string `json:"mount_point"`

	// Properties map
	Properties map[string]string `json:"properties"`
}

// StorageStatus represents the status of a storage resource
type StorageStatus struct {
	// Resource identifier
	ID string `json:"id"`

	// Resource type
	Type StorageType `json:"type"`

	// Current state
	State string `json:"state"`

	// Size information
	TotalSize     int64   `json:"total_size"`
	UsedSize      int64   `json:"used_size"`
	AvailableSize int64   `json:"available_size"`
	UsagePercent  float64 `json:"usage_percent"`

	// Mount information
	Mounted    bool   `json:"mounted"`
	MountPoint string `json:"mount_point"`

	// Health status
	Health string `json:"health"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata"`

	// Last updated timestamp
	UpdatedAt time.Time `json:"updated_at"`
}

// DiskInfo represents information about a disk device
type DiskInfo struct {
	// Device path (e.g., /dev/sda)
	Device string `json:"device"`

	// Size in bytes
	Size int64 `json:"size"`

	// Model name
	Model string `json:"model"`

	// Serial number
	Serial string `json:"serial"`

	// Vendor
	Vendor string `json:"vendor"`

	// Type (HDD, SSD, NVMe)
	Type string `json:"type"`

	// Current usage
	InUse bool `json:"in_use"`

	// Filesystem if formatted
	Filesystem string `json:"filesystem"`

	// Mount point if mounted
	MountPoint string `json:"mount_point"`

	// SMART health status
	SmartStatus string `json:"smart_status"`

	// Partitions
	Partitions []PartitionInfo `json:"partitions"`
}

// PartitionInfo represents information about a disk partition
type PartitionInfo struct {
	// Partition device (e.g., /dev/sda1)
	Device string `json:"device"`

	// Partition number
	Number int `json:"number"`

	// Start sector
	Start int64 `json:"start"`

	// End sector
	End int64 `json:"end"`

	// Size in bytes
	Size int64 `json:"size"`

	// Filesystem type
	Filesystem string `json:"filesystem"`

	// Mount point if mounted
	MountPoint string `json:"mount_point"`

	// UUID
	UUID string `json:"uuid"`

	// Label
	Label string `json:"label"`
}

// BackupConfig represents configuration for backup operations
type BackupConfig struct {
	// Source path to backup
	SourcePath string `json:"source_path"`

	// Destination path or URL
	DestinationPath string `json:"destination_path"`

	// Backup type (full, incremental, differential)
	Type string `json:"type"`

	// Compression settings
	Compression     bool   `json:"compression"`
	CompressionType string `json:"compression_type"`

	// Encryption settings
	Encryption    bool   `json:"encryption"`
	EncryptionKey string `json:"encryption_key"`

	// Retention policy
	RetentionDays int `json:"retention_days"`

	// Exclude patterns
	ExcludePatterns []string `json:"exclude_patterns"`
}

// SaltStackConfig represents Salt-specific configuration
type SaltStackConfig struct {
	// Target minion(s)
	Target string `json:"target"`

	// Salt state to apply
	State string `json:"state"`

	// Pillar data
	Pillar map[string]interface{} `json:"pillar"`

	// Test mode (dry run)
	Test bool `json:"test"`

	// Timeout for Salt operations
	Timeout time.Duration `json:"timeout"`
}

// TerraformConfig represents Terraform-specific configuration
type TerraformConfig struct {
	// Working directory
	WorkingDir string `json:"working_dir"`

	// Variables to pass
	Variables map[string]string `json:"variables"`

	// Backend configuration
	Backend map[string]interface{} `json:"backend"`

	// Auto-approve changes
	AutoApprove bool `json:"auto_approve"`
}

// VersionInfo represents version information for tools
type VersionInfo struct {
	// Tool name
	Tool string `json:"tool"`

	// Current version
	Current *version.Version `json:"current"`

	// Latest available version
	Latest *version.Version `json:"latest"`

	// Update available
	UpdateAvailable bool `json:"update_available"`
}

// StorageMetrics represents performance metrics
type StorageMetrics struct {
	// I/O operations per second
	IOPS int64 `json:"iops"`

	// Read throughput (bytes/sec)
	ReadThroughput int64 `json:"read_throughput"`

	// Write throughput (bytes/sec)
	WriteThroughput int64 `json:"write_throughput"`

	// Latency in microseconds
	Latency int64 `json:"latency"`

	// Queue depth
	QueueDepth int `json:"queue_depth"`

	// Utilization percentage
	Utilization float64 `json:"utilization"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`
}

// StorageAlert represents a storage-related alert
type StorageAlert struct {
	// Alert ID
	ID string `json:"id"`

	// Severity (critical, warning, info)
	Severity string `json:"severity"`

	// Alert type
	Type string `json:"type"`

	// Affected resource
	Resource string `json:"resource"`

	// Alert message
	Message string `json:"message"`

	// Threshold that triggered the alert
	Threshold float64 `json:"threshold"`

	// Current value
	CurrentValue float64 `json:"current_value"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`
}

// ResizeOperation represents a resize operation
type ResizeOperation struct {
	// Target device or volume
	Target string `json:"target"`

	// Current size
	CurrentSize int64 `json:"current_size"`

	// New size
	NewSize int64 `json:"new_size"`

	// Resize type (grow, shrink)
	Type string `json:"type"`

	// Online resize supported
	OnlineResize bool `json:"online_resize"`

	// Estimated duration
	EstimatedDuration time.Duration `json:"estimated_duration"`
}

// StorageManager interface defines common storage operations
type StorageManager interface {
	// Create a new storage resource
	Create(config StorageConfig) error

	// Read storage resource information
	Read(id string) (*StorageStatus, error)

	// Update storage resource
	Update(id string, config StorageConfig) error

	// Delete storage resource
	Delete(id string) error

	// List all storage resources
	List() ([]*StorageStatus, error)

	// Get metrics for a storage resource
	GetMetrics(id string) (*StorageMetrics, error)

	// Resize a storage resource
	Resize(operation ResizeOperation) error

	// Check health of storage resource
	CheckHealth(id string) error
}

// Constants for common operations
const (
	// Default filesystem mount options
	DefaultMountOptions = "defaults,noatime"

	// Storage thresholds
	WarningThreshold  = 70.0
	CriticalThreshold = 85.0

	// Performance thresholds
	HighIOPSThreshold    = 10000
	HighLatencyThreshold = 10000 // microseconds

	// Health states (moved to types_constants.go with proper type)

	// Operation types
	OperationCreate = "create"
	OperationResize = "resize"
	OperationDelete = "delete"
	OperationBackup = "backup"
)


// Essential types for storage interfaces

// StorageInfo represents basic storage information
type StorageInfo struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Device       string            `json:"device"`
	Type         StorageType       `json:"type"`
	Size         int64             `json:"size"`
	TotalSize    int64             `json:"total_size"`
	UsagePercent float64           `json:"usage_percent"`
	MountPoint   string            `json:"mount_point"`
	Filesystem   FilesystemType    `json:"filesystem"`
	Status       HealthStatus      `json:"status"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// VolumeConfig represents volume configuration
type VolumeConfig struct {
	Name         string            `json:"name"`
	Size         int64             `json:"size"`
	Filesystem   FilesystemType    `json:"filesystem"`
	Options      map[string]string `json:"options"`
	Type         StorageType       `json:"type"`
	Workload     string            `json:"workload"`
	MountPoint   string            `json:"mount_point"`
	MountOptions []string          `json:"mount_options"`
	DriverConfig DriverConfig      `json:"driver_config"`
	Encryption   bool              `json:"encryption"`
}

// VolumeInfo represents volume information
type VolumeInfo struct {
	StorageInfo                   // Embedded StorageInfo
	Name        string            `json:"name"`
	TotalSize   int64             `json:"total_size"`
	CreatedAt   time.Time         `json:"created_at"`
	Type        StorageType       `json:"type"`
	State       StorageState      `json:"state"`
	Device      string            `json:"device"`
	IsEncrypted bool              `json:"is_encrypted"`
}

// VolumeFilter represents filters for volume listing
type VolumeFilter struct {
	Type        *StorageType      `json:"type,omitempty"`
	Types       []StorageType     `json:"types,omitempty"`
	Filesystem  *FilesystemType   `json:"filesystem,omitempty"`
	Status      *HealthStatus     `json:"status,omitempty"`
	States      []StorageState    `json:"states,omitempty"`
	NamePrefix  string            `json:"name_prefix,omitempty"`
	MinSize     *int64            `json:"min_size,omitempty"`
	MaxSize     *int64            `json:"max_size,omitempty"`
	MountPoint  *string           `json:"mount_point,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// VolumeUpdate represents volume update operations
type VolumeUpdate struct {
	Size    *int64            `json:"size,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

// VolumeMetrics represents volume performance metrics
type VolumeMetrics struct {
	IOPS            int64     `json:"iops"`
	ReadThroughput  int64     `json:"read_throughput"`
	WriteThroughput int64     `json:"write_throughput"`
	Latency         int64     `json:"latency"`
	Utilization     float64   `json:"utilization"`
	Timestamp       time.Time `json:"timestamp"`
}

// SnapshotInfo represents snapshot information
type SnapshotInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	VolumeID  string    `json:"volume_id"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

// BackupJob represents a backup job
type BackupJob struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	SourceID    string        `json:"source_id"`
	Destination string        `json:"destination"`
	Schedule    string        `json:"schedule"`
	Retention   time.Duration `json:"retention"`
	Status      string        `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
}

// BackupJobConfig represents backup job configuration
type BackupJobConfig struct {
	Name        string        `json:"name"`
	SourceID    string        `json:"source_id"`
	Destination string        `json:"destination"`
	Schedule    string        `json:"schedule"`
	Retention   time.Duration `json:"retention"`
	Options     map[string]interface{} `json:"options"`
}

// BackupRun represents a backup execution
type BackupRun struct {
	ID        string    `json:"id"`
	JobID     string    `json:"job_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Status    string    `json:"status"`
	Size      int64     `json:"size"`
	Error     string    `json:"error,omitempty"`
}

// Additional interface types
type MetricsHistory struct {
	ResourceID string          `json:"resource_id"`
	StartTime  time.Time       `json:"start_time"`
	EndTime    time.Time       `json:"end_time"`
	Metrics    []StorageMetrics `json:"metrics"`
}

type GrowthPrediction struct {
	ResourceID        string        `json:"resource_id"`
	PredictedGrowth   float64       `json:"predicted_growth"`
	TimeToCapacity    time.Duration `json:"time_to_capacity"`
	Confidence        float64       `json:"confidence"`
	RecommendedAction string        `json:"recommended_action"`
}

type SystemHealthReport struct {
	OverallStatus   HealthStatus      `json:"overall_status"`
	CheckTime       time.Time         `json:"check_time"`
	Issues          []HealthIssue     `json:"issues"`
	Recommendations []string          `json:"recommendations"`
}

type HealthIssue struct {
	Severity    string `json:"severity"`
	Component   string `json:"component"`
	Description string `json:"description"`
	Resolution  string `json:"resolution"`
}

type ResourceHealthReport struct {
	ResourceID string                 `json:"resource_id"`
	Status     HealthStatus           `json:"status"`
	CheckTime  time.Time              `json:"check_time"`
	Metrics    map[string]interface{} `json:"metrics"`
}

type HealthRecommendation struct {
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// DiskHealth represents disk health status
type DiskHealth struct {
	Device       string    `json:"device"`
	Status       string    `json:"status"`
	Temperature  int       `json:"temperature"`
	PowerOnHours int64     `json:"power_on_hours"`
	LastCheck    time.Time `json:"last_check"`
	Errors       []string  `json:"errors"`
}

type StoragePolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Rules       []PolicyRule           `json:"rules"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type PolicyRule struct {
	Condition string      `json:"condition"`
	Action    string      `json:"action"`
	Value     interface{} `json:"value"`
}

type PolicyViolation struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id"`
	ResourceID  string    `json:"resource_id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	DetectedAt  time.Time `json:"detected_at"`
}

type StorageRequirements struct {
	MinSize     int64         `json:"min_size"`
	MaxSize     int64         `json:"max_size"`
	Performance string        `json:"performance"`
	Redundancy  string        `json:"redundancy"`
	Filesystem  FilesystemType `json:"filesystem"`
}

type StorageDeployment struct {
	ID          string                 `json:"id"`
	Workload    string                 `json:"workload"`
	Components  []StorageInfo          `json:"components"`
	Status      string                 `json:"status"`
	DeployedAt  time.Time              `json:"deployed_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type MigrationOptions struct {
	Method      string            `json:"method"`
	Bandwidth   int64             `json:"bandwidth"`
	Verify      bool              `json:"verify"`
	Options     map[string]string `json:"options"`
}

type OptimizationReport struct {
	GeneratedAt     time.Time                `json:"generated_at"`
	Recommendations []OptimizationRecommendation `json:"recommendations"`
	PotentialSavings int64                   `json:"potential_savings"`
}

type OptimizationRecommendation struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Action      string `json:"action"`
}

type DRPlan struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Components  []string               `json:"components"`
	Procedures  []DRProcedure          `json:"procedures"`
	CreatedAt   time.Time              `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type DRProcedure struct {
	Step        int    `json:"step"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Timeout     time.Duration `json:"timeout"`
}

type ValidationRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
}

type SystemInfo struct {
	OS           string            `json:"os"`
	Kernel       string            `json:"kernel"`
	Architecture string            `json:"architecture"`
	Memory       int64             `json:"memory"`
	CPU          string            `json:"cpu"`
	Features     map[string]bool   `json:"features"`
}

// Interface types for filesystem operations
type FilesystemOptions struct {
	Label       string            `json:"label,omitempty"`
	BlockSize   int               `json:"block_size,omitempty"`
	InodeRatio  int               `json:"inode_ratio,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
}

type FilesystemInfo struct {
	Device     string         `json:"device"`
	Type       FilesystemType `json:"type"`
	Label      string         `json:"label"`
	UUID       string         `json:"uuid"`
	Size       int64          `json:"size"`
	Used       int64          `json:"used"`
	Available  int64          `json:"available"`
	MountPoint string         `json:"mount_point"`
}

type UsageInfo struct {
	Total     int64   `json:"total"`
	Used      int64   `json:"used"`
	Available int64   `json:"available"`
	Percent   float64 `json:"percent"`
	Inodes    *InodeInfo `json:"inodes,omitempty"`
}

type InodeInfo struct {
	Total     int64   `json:"total"`
	Used      int64   `json:"used"`
	Available int64   `json:"available"`
	Percent   float64 `json:"percent"`
}

type MountEntry struct {
	Device     string   `json:"device"`
	MountPoint string   `json:"mount_point"`
	Filesystem string   `json:"filesystem"`
	Options    []string `json:"options"`
}

// Validation constants
const (
	MinVolumeSize      = 1 << 30 // 1GB minimum
	MaxVolumeSize      = 1 << 50 // 1PB maximum
	MaxLabelLength     = 255
	MaxMountPathLength = 4096
)
