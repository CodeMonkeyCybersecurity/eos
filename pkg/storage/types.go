package storage

import (
	"context"
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

// MountPoint represents a mount point with its characteristics
type MountPoint struct {
	Path     string `json:"path"`     // Mount path
	Readonly bool   `json:"readonly"` // Whether mounted read-only
}

// DiskInfo represents comprehensive information about a disk device
// This unified type consolidates all disk information across Eos storage subsystems
type DiskInfo struct {
	// Basic device information
	Device      string `json:"device"`      // Device path (e.g., /dev/sda)
	Name        string `json:"name"`        // Human-readable name
	Description string `json:"description"` // Device description

	// Size information
	Size      int64  `json:"size"`       // Size in bytes
	SizeHuman string `json:"size_human"` // Human-readable size (e.g., "1TB")

	// Hardware information
	Model         string `json:"model"`          // Model name
	Serial        string `json:"serial"`         // Serial number
	Vendor        string `json:"vendor"`         // Vendor/manufacturer
	MediaType     string `json:"media_type"`     // SSD, HDD, NVMe, etc.
	ConnectionBus string `json:"connection_bus"` // SATA, NVMe, USB, etc.

	// Device characteristics
	IsRemovable bool `json:"is_removable"` // Whether device is removable
	IsUSB       bool `json:"is_usb"`       // Whether device is USB
	Removable   bool `json:"removable"`    // Alternative removable flag for compatibility

	// Usage and status
	InUse       bool   `json:"in_use"`       // Whether device is currently in use
	Filesystem  string `json:"filesystem"`   // Filesystem type if formatted
	MountPoint  string `json:"mount_point"`  // Primary mount point if mounted
	SmartStatus string `json:"smart_status"` // SMART health status

	// Collections
	Mountpoints []MountPoint    `json:"mountpoints"` // All mount points
	Partitions  []PartitionInfo `json:"partitions"`  // Partition information

	// Health and metadata
	Health     *DiskHealth       `json:"health,omitempty"` // Detailed health information
	Properties map[string]string `json:"properties"`       // Additional properties
	Metadata   map[string]string `json:"metadata"`         // Additional metadata

	// Timestamps
	LastUpdated time.Time `json:"last_updated"` // When this information was last updated
}

// PartitionInfo represents comprehensive information about a disk partition
// This unified type consolidates all partition information across Eos storage subsystems
type PartitionInfo struct {
	// Basic partition information
	Device string `json:"device"` // Partition device (e.g., /dev/sda1)
	Number int    `json:"number"` // Partition number

	// Geometry information
	Start uint64 `json:"start"` // Start sector
	End   uint64 `json:"end"`   // End sector
	Size  uint64 `json:"size"`  // Size in bytes

	// Size formatting
	SizeHuman string `json:"size_human"` // Human-readable size (e.g., "100GB")

	// Partition characteristics
	Type       string   `json:"type"`       // Partition type (primary, extended, logical)
	Filesystem string   `json:"filesystem"` // Filesystem type
	Label      string   `json:"label"`      // Partition label
	UUID       string   `json:"uuid"`       // Partition UUID
	Flags      []string `json:"flags"`      // Partition flags (boot, lvm, etc.)

	// Mount information
	IsMounted  bool   `json:"is_mounted"`  // Whether partition is currently mounted
	MountPoint string `json:"mount_point"` // Mount point if mounted

	// Security and features
	Encrypted bool `json:"encrypted"` // Whether partition is encrypted

	// Timestamps
	Timestamp time.Time `json:"timestamp"` // When this information was collected
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

// Config represents -specific configuration
type Config struct {
	// Target minion(s)
	Target string `json:"target"`

	//  state to apply
	State string `json:"state"`

	// Additional data
	Data map[string]interface{} `json:"data"`

	// Test mode (dry run)
	Test bool `json:"test"`

	// Timeout for  operations
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
	Create(ctx context.Context, config StorageConfig) error

	// Read storage resource information
	Read(ctx context.Context, id string) (*StorageStatus, error)

	// Update storage resource
	Update(ctx context.Context, id string, config StorageConfig) error

	// Delete storage resource
	Delete(ctx context.Context, id string) error

	// List all storage resources
	List(ctx context.Context) ([]*StorageStatus, error)

	// Get metrics for a storage resource
	GetMetrics(ctx context.Context, id string) (*StorageMetrics, error)

	// Resize a storage resource
	Resize(ctx context.Context, operation ResizeOperation) error

	// Check health of storage resource
	CheckHealth(ctx context.Context, id string) (*HealthStatus, error)
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
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Device       string                 `json:"device"`
	Type         StorageType            `json:"type"`
	Size         int64                  `json:"size"`
	TotalSize    int64                  `json:"total_size"`
	UsagePercent float64                `json:"usage_percent"`
	MountPoint   string                 `json:"mount_point"`
	Filesystem   FilesystemType         `json:"filesystem"`
	Status       HealthStatus           `json:"status"`
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
	StorageInfo              // Embedded StorageInfo
	Name        string       `json:"name"`
	TotalSize   int64        `json:"total_size"`
	CreatedAt   time.Time    `json:"created_at"`
	Type        StorageType  `json:"type"`
	State       StorageState `json:"state"`
	Device      string       `json:"device"`
	IsEncrypted bool         `json:"is_encrypted"`
}

// VolumeFilter represents filters for volume listing
type VolumeFilter struct {
	Type       *StorageType      `json:"type,omitempty"`
	Types      []StorageType     `json:"types,omitempty"`
	Filesystem *FilesystemType   `json:"filesystem,omitempty"`
	Status     *HealthStatus     `json:"status,omitempty"`
	States     []StorageState    `json:"states,omitempty"`
	NamePrefix string            `json:"name_prefix,omitempty"`
	MinSize    *int64            `json:"min_size,omitempty"`
	MaxSize    *int64            `json:"max_size,omitempty"`
	MountPoint *string           `json:"mount_point,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
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
	Name        string                 `json:"name"`
	SourceID    string                 `json:"source_id"`
	Destination string                 `json:"destination"`
	Schedule    string                 `json:"schedule"`
	Retention   time.Duration          `json:"retention"`
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
	ResourceID string           `json:"resource_id"`
	StartTime  time.Time        `json:"start_time"`
	EndTime    time.Time        `json:"end_time"`
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
	OverallStatus   HealthStatus  `json:"overall_status"`
	CheckTime       time.Time     `json:"check_time"`
	Issues          []HealthIssue `json:"issues"`
	Recommendations []string      `json:"recommendations"`
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

// DiskHealth represents comprehensive disk health status
// This unified type consolidates disk health information across Eos storage subsystems
type DiskHealth struct {
	Device       string            `json:"device"`         // Device path
	Status       string            `json:"status"`         // healthy, warning, critical
	Temperature  int               `json:"temperature"`    // Temperature in Celsius
	PowerOnHours uint64            `json:"power_on_hours"` // Total power-on hours
	LastCheck    time.Time         `json:"last_check"`     // When health was last checked
	Errors       []string          `json:"errors"`         // Health check errors
	SmartData    map[string]string `json:"smart_data"`     // SMART attribute data
}

type StoragePolicy struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Rules     []PolicyRule           `json:"rules"`
	Enabled   bool                   `json:"enabled"`
	CreatedAt time.Time              `json:"created_at"`
	Metadata  map[string]interface{} `json:"metadata"`
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
	MinSize     int64          `json:"min_size"`
	MaxSize     int64          `json:"max_size"`
	Performance string         `json:"performance"`
	Redundancy  string         `json:"redundancy"`
	Filesystem  FilesystemType `json:"filesystem"`
}

type StorageDeployment struct {
	ID         string                 `json:"id"`
	Workload   string                 `json:"workload"`
	Components []StorageInfo          `json:"components"`
	Status     string                 `json:"status"`
	DeployedAt time.Time              `json:"deployed_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type MigrationOptions struct {
	Method    string            `json:"method"`
	Bandwidth int64             `json:"bandwidth"`
	Verify    bool              `json:"verify"`
	Options   map[string]string `json:"options"`
}

type OptimizationReport struct {
	GeneratedAt      time.Time                    `json:"generated_at"`
	Recommendations  []OptimizationRecommendation `json:"recommendations"`
	PotentialSavings int64                        `json:"potential_savings"`
}

type OptimizationRecommendation struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Action      string `json:"action"`
}

type DRPlan struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Components []string               `json:"components"`
	Procedures []DRProcedure          `json:"procedures"`
	CreatedAt  time.Time              `json:"created_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type DRProcedure struct {
	Step        int           `json:"step"`
	Description string        `json:"description"`
	Action      string        `json:"action"`
	Timeout     time.Duration `json:"timeout"`
}

type ValidationRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
}

type SystemInfo struct {
	OS           string          `json:"os"`
	Kernel       string          `json:"kernel"`
	Architecture string          `json:"architecture"`
	Memory       int64           `json:"memory"`
	CPU          string          `json:"cpu"`
	Features     map[string]bool `json:"features"`
}

// Interface types for filesystem operations
type FilesystemOptions struct {
	Label      string            `json:"label,omitempty"`
	BlockSize  int               `json:"block_size,omitempty"`
	InodeRatio int               `json:"inode_ratio,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
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
	Total     int64      `json:"total"`
	Used      int64      `json:"used"`
	Available int64      `json:"available"`
	Percent   float64    `json:"percent"`
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

// =============================================================================
// DISK MANAGEMENT TYPES
// Consolidated from pkg/disk_management - provides disk operation types
// =============================================================================

// DiskListResult contains results of listing disks
type DiskListResult struct {
	Disks     []DiskInfo `json:"disks"`
	Total     int        `json:"total"`
	Timestamp time.Time  `json:"timestamp"`
}

// PartitionListResult contains results of listing partitions
type PartitionListResult struct {
	DiskPath   string          `json:"disk_path"`
	Partitions []PartitionInfo `json:"partitions"`
	Timestamp  time.Time       `json:"timestamp"`
}

// MountedVolume represents a currently mounted volume
type MountedVolume struct {
	Device     string `json:"device"`
	MountPoint string `json:"mount_point"`
	Filesystem string `json:"filesystem"`
	Options    string `json:"options"`
}

// PartitionOperation represents a partition management operation
type PartitionOperation struct {
	Operation string        `json:"operation"` // create, format, mount, unmount
	Device    string        `json:"device"`
	Target    string        `json:"target"`
	Success   bool          `json:"success"`
	Message   string        `json:"message"`
	Output    string        `json:"output,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	DryRun    bool          `json:"dry_run"`
}

// PartitionOptions contains options for partition operations
type PartitionOptions struct {
	PartitionType  string `json:"partition_type"` // primary, extended, logical
	FileSystem     string `json:"filesystem"`     // ext4, xfs, btrfs, etc.
	Label          string `json:"label"`
	MountPoint     string `json:"mount_point"`
	MountOptions   string `json:"mount_options"`
	Force          bool   `json:"force"`
	DryRun         bool   `json:"dry_run"`
	AddToFstab     bool   `json:"add_to_fstab"`
	CreateMountDir bool   `json:"create_mount_dir"`
}

// DefaultPartitionOptions returns options with sensible defaults
func DefaultPartitionOptions() *PartitionOptions {
	return &PartitionOptions{
		PartitionType:  "primary",
		FileSystem:     "ext4",
		Force:          false,
		DryRun:         false,
		AddToFstab:     false,
		CreateMountDir: true,
	}
}

// DiskManagerConfig contains configuration for disk management
type DiskManagerConfig struct {
	RequireConfirmation  bool     `json:"require_confirmation" mapstructure:"require_confirmation"`
	SafetyChecks         bool     `json:"safety_checks" mapstructure:"safety_checks"`
	BackupPartitionTable bool     `json:"backup_partition_table" mapstructure:"backup_partition_table"`
	AllowRemovableMedia  bool     `json:"allow_removable_media" mapstructure:"allow_removable_media"`
	ExcludedDevices      []string `json:"excluded_devices" mapstructure:"excluded_devices"`
	DefaultFileSystem    string   `json:"default_filesystem" mapstructure:"default_filesystem"`
	DefaultMountBase     string   `json:"default_mount_base" mapstructure:"default_mount_base"`
}

// DefaultDiskManagerConfig returns a configuration with sensible defaults
func DefaultDiskManagerConfig() *DiskManagerConfig {
	return &DiskManagerConfig{
		RequireConfirmation:  true,
		SafetyChecks:         true,
		BackupPartitionTable: true,
		AllowRemovableMedia:  true,
		ExcludedDevices:      []string{"/dev/sda", "/dev/nvme0n1"}, // Common system disks
		DefaultFileSystem:    "ext4",
		DefaultMountBase:     "/mnt",
	}
}

// MountOperation represents a mount/unmount operation
type MountOperation struct {
	Operation  string        `json:"operation"` // mount, unmount
	Device     string        `json:"device"`
	MountPoint string        `json:"mount_point"`
	Success    bool          `json:"success"`
	Message    string        `json:"message"`
	Timestamp  time.Time     `json:"timestamp"`
	Duration   time.Duration `json:"duration"`
	DryRun     bool          `json:"dry_run"`
}

// FormatOperation represents a filesystem format operation
type FormatOperation struct {
	Device     string        `json:"device"`
	FileSystem string        `json:"filesystem"`
	Label      string        `json:"label"`
	Success    bool          `json:"success"`
	Message    string        `json:"message"`
	Output     string        `json:"output,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
	Duration   time.Duration `json:"duration"`
	DryRun     bool          `json:"dry_run"`
}

// =============================================================================
// DISK SAFETY TYPES
// Consolidated from pkg/disk_safety - provides safety and journaling types
// =============================================================================

// OperationStatus represents the status of a disk operation
type OperationStatus string

const (
	StatusPending    OperationStatus = "pending"
	StatusInProgress OperationStatus = "in_progress"
	StatusCompleted  OperationStatus = "completed"
	StatusFailed     OperationStatus = "failed"
	StatusRolledBack OperationStatus = "rolled_back"
)

// JournalEntry represents a logged disk operation
type JournalEntry struct {
	ID            string                 `json:"id"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time,omitempty"`
	OperationType string                 `json:"operation_type"`
	Target        DiskTarget             `json:"target"`
	Parameters    map[string]interface{} `json:"parameters"`
	PreState      *DiskState             `json:"pre_state"`
	PostState     *DiskState             `json:"post_state,omitempty"`
	Status        OperationStatus        `json:"status"`
	Commands      []ExecutedCommand      `json:"commands"`
	RollbackPlan  *RollbackPlan          `json:"rollback_plan,omitempty"`
	Snapshot      *Snapshot              `json:"snapshot,omitempty"`
	Error         string                 `json:"error,omitempty"`
	User          string                 `json:"user"`
	Checksum      string                 `json:"checksum"`
}

// DiskTarget identifies the target of a disk operation
type DiskTarget struct {
	Device      string `json:"device"`
	VolumeGroup string `json:"volume_group,omitempty"`
	LogicalVol  string `json:"logical_volume,omitempty"`
	Mountpoint  string `json:"mountpoint,omitempty"`
	Filesystem  string `json:"filesystem,omitempty"`
}

// DiskState captures the state of disk resources
type DiskState struct {
	Timestamp   time.Time                 `json:"timestamp"`
	LVMState    *LVMState                 `json:"lvm_state,omitempty"`
	Filesystems []FilesystemState         `json:"filesystems"`
	Mounts      []MountState              `json:"mounts"`
	BlockDevs   map[string]BlockDevice    `json:"block_devices"`
	DiskUsage   map[string]DiskUsageState `json:"disk_usage"`
}

// LVMState represents LVM configuration
type LVMState struct {
	PhysicalVolumes map[string]PVState `json:"physical_volumes"`
	VolumeGroups    map[string]VGState `json:"volume_groups"`
	LogicalVolumes  map[string]LVState `json:"logical_volumes"`
}

// PVState represents physical volume state
type PVState struct {
	Device      string `json:"device"`
	Size        int64  `json:"size"`
	Free        int64  `json:"free"`
	VGName      string `json:"vg_name"`
	UUID        string `json:"uuid"`
	Allocatable bool   `json:"allocatable"`
}

// VGState represents volume group state
type VGState struct {
	Name         string   `json:"name"`
	UUID         string   `json:"uuid"`
	Size         int64    `json:"size"`
	Free         int64    `json:"free"`
	ExtentSize   int64    `json:"extent_size"`
	ExtentCount  int      `json:"extent_count"`
	FreeExtents  int      `json:"free_extents"`
	PVCount      int      `json:"pv_count"`
	LVCount      int      `json:"lv_count"`
	MaxLV        int      `json:"max_lv"`
	MaxPV        int      `json:"max_pv"`
	PhysicalVols []string `json:"physical_volumes"`
}

// LVState represents logical volume state
type LVState struct {
	Name       string `json:"name"`
	VGName     string `json:"vg_name"`
	UUID       string `json:"uuid"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Active     bool   `json:"active"`
	Open       bool   `json:"open"`
	Attributes string `json:"attributes"`
	DevicePath string `json:"device_path"`
}

// FilesystemState represents filesystem state
type FilesystemState struct {
	Device      string `json:"device"`
	Type        string `json:"type"`
	Label       string `json:"label"`
	UUID        string `json:"uuid"`
	TotalSize   int64  `json:"total_size"`
	UsedSize    int64  `json:"used_size"`
	FreeSize    int64  `json:"free_size"`
	InodesTotal int64  `json:"inodes_total"`
	InodesFree  int64  `json:"inodes_free"`
}

// MountState represents mount point state
type MountState struct {
	Device     string   `json:"device"`
	Mountpoint string   `json:"mountpoint"`
	Filesystem string   `json:"filesystem"`
	Options    []string `json:"options"`
	Dump       int      `json:"dump"`
	Pass       int      `json:"pass"`
}

// DiskUsageState represents disk usage at a point in time
type DiskUsageState struct {
	Filesystem string  `json:"filesystem"`
	Size       int64   `json:"size"`
	Used       int64   `json:"used"`
	Available  int64   `json:"available"`
	UsePercent float64 `json:"use_percent"`
	Mountpoint string  `json:"mountpoint"`
}

// DiskUsageInfo represents disk usage information (alias for compatibility)
type DiskUsageInfo = DiskUsageState

// ExecutedCommand represents a command that was executed
type ExecutedCommand struct {
	Timestamp time.Time     `json:"timestamp"`
	Command   string        `json:"command"`
	Args      []string      `json:"args"`
	WorkDir   string        `json:"work_dir,omitempty"`
	Output    string        `json:"output"`
	Error     string        `json:"error,omitempty"`
	ExitCode  int           `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
}

// RollbackPlan describes how to rollback an operation
type RollbackPlan struct {
	Method        RollbackMethod    `json:"method"`
	SnapshotID    string            `json:"snapshot_id,omitempty"`
	Commands      []RollbackCommand `json:"commands,omitempty"`
	EstimatedTime time.Duration     `json:"estimated_time"`
	Description   string            `json:"description"`
}

// RollbackMethod describes the rollback approach
type RollbackMethod string

const (
	RollbackSnapshot RollbackMethod = "snapshot"
	RollbackReverse  RollbackMethod = "reverse"
	RollbackManual   RollbackMethod = "manual"
)

// RollbackCommand describes a command to execute for rollback
type RollbackCommand struct {
	Command     string   `json:"command"`
	Args        []string `json:"args"`
	Description string   `json:"description"`
	Critical    bool     `json:"critical"`
}

// Snapshot represents an LVM snapshot
type Snapshot struct {
	Name       string     `json:"name"`
	SourceVG   string     `json:"source_vg"`
	SourceLV   string     `json:"source_lv"`
	Size       int64      `json:"size"`
	Created    time.Time  `json:"created"`
	JournalID  string     `json:"journal_id"`
	AutoRemove bool       `json:"auto_remove"`
	RemoveAt   *time.Time `json:"remove_at,omitempty"`
}

// SafetyConfig represents configuration for safe storage operations
type SafetyConfig struct {
	RequireSnapshot       bool          `json:"require_snapshot"`
	SnapshotMinSize       int64         `json:"snapshot_min_size"`
	SnapshotRetention     time.Duration `json:"snapshot_retention"`
	MaxConcurrentOps      int           `json:"max_concurrent_ops"`
	PreflightChecks       bool          `json:"preflight_checks"`
	JournalRetention      time.Duration `json:"journal_retention"`
	BackupBeforeOperation bool          `json:"backup_before_operation"`
}

// DefaultSafetyConfig returns a conservative safety configuration
func DefaultSafetyConfig() *SafetyConfig {
	return &SafetyConfig{
		RequireSnapshot:       false,   // Allow operations without snapshots if VG space is limited
		SnapshotMinSize:       1 << 30, // 1GB
		SnapshotRetention:     24 * time.Hour,
		MaxConcurrentOps:      2,
		PreflightChecks:       true,
		JournalRetention:      7 * 24 * time.Hour, // 7 days
		BackupBeforeOperation: true,
	}
}
