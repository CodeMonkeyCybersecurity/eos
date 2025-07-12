package storage

import (
	"time"
)

// StorageInfo provides unified information about any storage resource
// This consolidates DiskInfo, VolumeInfo, PartitionInfo from various packages
type StorageInfo struct {
	// Common fields for all storage types
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Type        StorageType `json:"type"`
	Device      string      `json:"device"`       // Physical device path
	VirtualPath string      `json:"virtual_path"` // Logical path (e.g., /dev/vg/lv)
	UUID        string      `json:"uuid"`
	Label       string      `json:"label"`

	// Size information
	TotalSize     int64   `json:"total_size"`     // Total size in bytes
	UsedSize      int64   `json:"used_size"`      // Used size in bytes
	AvailableSize int64   `json:"available_size"` // Available size in bytes
	UsagePercent  float64 `json:"usage_percent"`

	// Filesystem information
	Filesystem   FilesystemType `json:"filesystem"`
	MountPoint   string         `json:"mount_point"`
	MountOptions []string       `json:"mount_options"`
	IsMounted    bool           `json:"is_mounted"`

	// Status information
	State       StorageState `json:"state"`
	Health      HealthStatus `json:"health"`
	IsEncrypted bool         `json:"is_encrypted"`
	IsReadOnly  bool         `json:"is_read_only"`

	// Performance characteristics
	IOPSLimit     int64  `json:"iops_limit"`
	ThroughputMBs int64  `json:"throughput_mbs"`
	StorageClass  string `json:"storage_class"` // fast-ssd, standard, archive

	// Relationships
	ParentID    string   `json:"parent_id"`    // For partitions, snapshots
	ChildrenIDs []string `json:"children_ids"` // For disks with partitions

	// Driver-specific metadata
	DriverMeta map[string]interface{} `json:"driver_meta"`

	// Timestamps
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	AccessedAt time.Time `json:"accessed_at"`
}

// VolumeInfo represents a logical volume (unified from various packages)
type VolumeInfo struct {
	StorageInfo

	// Volume-specific fields
	VolumeGroup string `json:"volume_group,omitempty"` // For LVM
	Pool        string `json:"pool,omitempty"`         // For ZFS/Ceph
	RaidLevel   string `json:"raid_level,omitempty"`   // For RAID configurations
	Replicas    int    `json:"replicas,omitempty"`     // For distributed storage

	// Snapshot information
	SnapshotOf string   `json:"snapshot_of,omitempty"`
	Snapshots  []string `json:"snapshots,omitempty"`

	// Backup information
	LastBackup   *time.Time `json:"last_backup,omitempty"`
	BackupPolicy string     `json:"backup_policy,omitempty"`
}

// DiskHealth consolidates health information from various sources
type DiskHealth struct {
	Device       string                 `json:"device"`
	HealthStatus HealthStatus           `json:"health_status"`
	Temperature  int                    `json:"temperature"`
	PowerOnHours int64                  `json:"power_on_hours"`
	ErrorCount   int64                  `json:"error_count"`
	SmartStatus  string                 `json:"smart_status"`
	Attributes   map[string]interface{} `json:"attributes"`
	LastChecked  time.Time              `json:"last_checked"`
}

// MountEntry represents a mounted filesystem (consolidates various mount types)
type MountEntry struct {
	Device     string   `json:"device"`
	MountPoint string   `json:"mount_point"`
	Filesystem string   `json:"filesystem"`
	Options    []string `json:"options"`
	IsReadOnly bool     `json:"is_read_only"`
	IsNetwork  bool     `json:"is_network"`
}

// FstabEntryDetailed represents a detailed entry in /etc/fstab
// This extends the basic FstabEntry with additional metadata
type FstabEntryDetailed struct {
	Device     string `json:"device"`
	MountPoint string `json:"mount_point"`
	Filesystem string `json:"filesystem"`
	Options    string `json:"options"`
	Dump       int    `json:"dump"`
	Pass       int    `json:"pass"`
	Comment    string `json:"comment,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Label      string `json:"label,omitempty"`
}

// UsageInfo provides detailed usage statistics
type UsageInfo struct {
	MountPoint     string  `json:"mount_point"`
	TotalBytes     int64   `json:"total_bytes"`
	UsedBytes      int64   `json:"used_bytes"`
	AvailableBytes int64   `json:"available_bytes"`
	UsagePercent   float64 `json:"usage_percent"`

	// Inode information
	TotalInodes  int64   `json:"total_inodes"`
	UsedInodes   int64   `json:"used_inodes"`
	FreeInodes   int64   `json:"free_inodes"`
	InodePercent float64 `json:"inode_percent"`

	// Additional metrics
	ReservedBytes int64     `json:"reserved_bytes"`
	Timestamp     time.Time `json:"timestamp"`
}

// VolumeConfig unified configuration for creating volumes
type VolumeConfig struct {
	Name         string         `json:"name"`
	Type         StorageType    `json:"type"`
	Size         int64          `json:"size"`
	Filesystem   FilesystemType `json:"filesystem"`
	MountPoint   string         `json:"mount_point"`
	MountOptions []string       `json:"mount_options"`

	// Workload optimization
	Workload string `json:"workload"` // database, backup, container, etc.

	// Performance requirements
	MinIOPS       int64 `json:"min_iops,omitempty"`
	MinThroughput int64 `json:"min_throughput_mbs,omitempty"`

	// Reliability requirements
	Redundancy string `json:"redundancy,omitempty"` // none, mirror, raidz, etc.
	Encryption bool   `json:"encryption"`

	// Driver-specific configuration
	DriverConfig map[string]interface{} `json:"driver_config"`
}

// VolumeUpdate represents updates to apply to a volume
type VolumeUpdate struct {
	NewSize      *int64                 `json:"new_size,omitempty"`
	MountPoint   *string                `json:"mount_point,omitempty"`
	MountOptions []string               `json:"mount_options,omitempty"`
	Label        *string                `json:"label,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// VolumeFilter for listing volumes
type VolumeFilter struct {
	Types      []StorageType  `json:"types,omitempty"`
	States     []StorageState `json:"states,omitempty"`
	Workloads  []string       `json:"workloads,omitempty"`
	MinSize    *int64         `json:"min_size,omitempty"`
	MaxSize    *int64         `json:"max_size,omitempty"`
	MountPoint *string        `json:"mount_point,omitempty"`
	Labels     []string       `json:"labels,omitempty"`
}

// PartitionConfig for creating partitions
type PartitionConfig struct {
	Number     int            `json:"number"`
	StartMB    int64          `json:"start_mb"`
	SizeMB     int64          `json:"size_mb"`
	Type       string         `json:"type"` // primary, extended, logical
	Filesystem FilesystemType `json:"filesystem,omitempty"`
	Label      string         `json:"label,omitempty"`
	Flags      []string       `json:"flags,omitempty"` // boot, lvm, raid, etc.
}

// FilesystemOptions for creating filesystems
type FilesystemOptions struct {
	BlockSize    int               `json:"block_size,omitempty"`
	InodeSize    int               `json:"inode_size,omitempty"`
	Label        string            `json:"label,omitempty"`
	UUID         string            `json:"uuid,omitempty"`
	Features     []string          `json:"features,omitempty"`
	MountOptions []string          `json:"mount_options,omitempty"`
	ReservedPct  float64           `json:"reserved_pct,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
}

// FilesystemInfo provides detailed filesystem information
type FilesystemInfo struct {
	Device      string                 `json:"device"`
	Type        FilesystemType         `json:"type"`
	Label       string                 `json:"label"`
	UUID        string                 `json:"uuid"`
	State       string                 `json:"state"`
	Version     string                 `json:"version"`
	Features    []string               `json:"features"`
	BlockSize   int                    `json:"block_size"`
	FragPercent float64                `json:"frag_percent"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SnapshotInfo represents a storage snapshot
type SnapshotInfo struct {
	Name        string    `json:"name"`
	SourceID    string    `json:"source_id"`
	Created     time.Time `json:"created"`
	Size        int64     `json:"size"`
	State       string    `json:"state"`
	Description string    `json:"description"`
	IsAutomatic bool      `json:"is_automatic"`
}

// BackupJobConfig configures a backup job
type BackupJobConfig struct {
	Name            string   `json:"name"`
	SourceID        string   `json:"source_id"`
	Destination     string   `json:"destination"`
	Schedule        string   `json:"schedule"` // cron expression
	RetentionDays   int      `json:"retention_days"`
	Compression     bool     `json:"compression"`
	Encryption      bool     `json:"encryption"`
	EncryptionKey   string   `json:"encryption_key,omitempty"`
	PreScript       string   `json:"pre_script,omitempty"`
	PostScript      string   `json:"post_script,omitempty"`
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
	BackupType      string   `json:"backup_type"` // full, incremental, differential
}

// BackupJob represents a configured backup job
type BackupJob struct {
	ID           string          `json:"id"`
	Config       BackupJobConfig `json:"config"`
	State        string          `json:"state"`
	LastRun      *time.Time      `json:"last_run"`
	NextRun      *time.Time      `json:"next_run"`
	SuccessCount int             `json:"success_count"`
	FailureCount int             `json:"failure_count"`
}

// BackupRun represents a single backup execution
type BackupRun struct {
	ID          string        `json:"id"`
	JobID       string        `json:"job_id"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     *time.Time    `json:"end_time"`
	State       string        `json:"state"`
	BytesBackup int64         `json:"bytes_backup"`
	Duration    time.Duration `json:"duration"`
	Error       string        `json:"error,omitempty"`
}

// VolumeMetrics provides detailed volume metrics
type VolumeMetrics struct {
	VolumeID  string    `json:"volume_id"`
	Timestamp time.Time `json:"timestamp"`

	// I/O metrics
	ReadOps    int64 `json:"read_ops"`
	WriteOps   int64 `json:"write_ops"`
	ReadBytes  int64 `json:"read_bytes"`
	WriteBytes int64 `json:"write_bytes"`

	// Latency metrics (microseconds)
	ReadLatency  int64 `json:"read_latency"`
	WriteLatency int64 `json:"write_latency"`

	// Queue metrics
	QueueDepth   int     `json:"queue_depth"`
	AvgQueueSize float64 `json:"avg_queue_size"`

	// Utilization
	Utilization float64 `json:"utilization"`
	Saturation  float64 `json:"saturation"`
}

// MetricsHistory provides historical metrics
type MetricsHistory struct {
	VolumeID   string          `json:"volume_id"`
	StartTime  time.Time       `json:"start_time"`
	EndTime    time.Time       `json:"end_time"`
	Resolution string          `json:"resolution"` // 1m, 5m, 1h, etc.
	Metrics    []VolumeMetrics `json:"metrics"`
}

// GrowthPrediction predicts future storage growth
type GrowthPrediction struct {
	VolumeID         string    `json:"volume_id"`
	CurrentUsage     int64     `json:"current_usage"`
	PredictedUsage   int64     `json:"predicted_usage"`
	DaysUntilFull    int       `json:"days_until_full"`
	GrowthRatePerDay int64     `json:"growth_rate_per_day"`
	Confidence       float64   `json:"confidence"`
	PredictionDate   time.Time `json:"prediction_date"`
}

// HealthReport provides comprehensive health information
type HealthReport struct {
	VolumeID      string            `json:"volume_id"`
	OverallHealth HealthStatus      `json:"overall_health"`
	Components    []ComponentHealth `json:"components"`
	Issues        []HealthIssue     `json:"issues"`
	CheckedAt     time.Time         `json:"checked_at"`
}

// ComponentHealth represents health of a storage component
type ComponentHealth struct {
	Name    string                 `json:"name"`
	Type    string                 `json:"type"`
	Status  HealthStatus           `json:"status"`
	Details map[string]interface{} `json:"details"`
}

// HealthIssue represents a specific health issue
type HealthIssue struct {
	Severity    string `json:"severity"`
	Component   string `json:"component"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Resolution  string `json:"resolution"`
}

// SystemHealthReport provides system-wide storage health
type SystemHealthReport struct {
	OverallHealth   HealthStatus   `json:"overall_health"`
	TotalStorage    int64          `json:"total_storage"`
	UsedStorage     int64          `json:"used_storage"`
	HealthyVolumes  int            `json:"healthy_volumes"`
	DegradedVolumes int            `json:"degraded_volumes"`
	FailedVolumes   int            `json:"failed_volumes"`
	Alerts          []StorageAlert `json:"alerts"`
	Volumes         []HealthReport `json:"volumes"`
	CheckedAt       time.Time      `json:"checked_at"`
}

// ResourceHealthReport provides health for a specific resource
type ResourceHealthReport struct {
	ResourceID   string         `json:"resource_id"`
	ResourceType string         `json:"resource_type"`
	Health       HealthStatus   `json:"health"`
	Metrics      *VolumeMetrics `json:"metrics,omitempty"`
	Issues       []HealthIssue  `json:"issues"`
	History      []HealthStatus `json:"history"`
	CheckedAt    time.Time      `json:"checked_at"`
}

// HealthRecommendation provides actionable health recommendations
type HealthRecommendation struct {
	ID                  string `json:"id"`
	ResourceID          string `json:"resource_id"`
	Priority            string `json:"priority"` // critical, high, medium, low
	Category            string `json:"category"` // performance, reliability, capacity
	Description         string `json:"description"`
	Impact              string `json:"impact"`
	Action              string `json:"action"`
	AutomationAvailable bool   `json:"automation_available"`
	EstimatedTime       string `json:"estimated_time"`
}

// StoragePolicy defines storage policies
type StoragePolicy struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"`  // quota, placement, retention, etc.
	Scope     string         `json:"scope"` // global, volume, user, etc.
	Rules     []PolicyRule   `json:"rules"`
	Actions   []PolicyAction `json:"actions"`
	Enabled   bool           `json:"enabled"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// PolicyRule defines a policy rule
type PolicyRule struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// PolicyAction defines what happens when policy is triggered
type PolicyAction struct {
	Type       string                 `json:"type"` // alert, resize, migrate, etc.
	Parameters map[string]interface{} `json:"parameters"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID   string     `json:"policy_id"`
	PolicyName string     `json:"policy_name"`
	ResourceID string     `json:"resource_id"`
	Violation  string     `json:"violation"`
	Severity   string     `json:"severity"`
	DetectedAt time.Time  `json:"detected_at"`
	Resolved   bool       `json:"resolved"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// StorageDeployment represents a complete storage deployment
type StorageDeployment struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Workload   string                 `json:"workload"`
	Components []DeploymentComponent  `json:"components"`
	Status     string                 `json:"status"`
	CreatedAt  time.Time              `json:"created_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// DeploymentComponent represents a component in a storage deployment
type DeploymentComponent struct {
	Name     string      `json:"name"`
	Type     StorageType `json:"type"`
	VolumeID string      `json:"volume_id"`
	Role     string      `json:"role"` // primary, cache, backup, etc.
	Config   interface{} `json:"config"`
}

// StorageRequirements defines requirements for storage deployment
type StorageRequirements struct {
	Capacity    int64             `json:"capacity"`
	Performance PerformanceReqs   `json:"performance"`
	Reliability ReliabilityReqs   `json:"reliability"`
	Compliance  []string          `json:"compliance"`
	Budget      *BudgetConstraint `json:"budget,omitempty"`
}

// PerformanceReqs defines performance requirements
type PerformanceReqs struct {
	MinIOPS       int64  `json:"min_iops"`
	MinThroughput int64  `json:"min_throughput_mbs"`
	MaxLatency    int64  `json:"max_latency_ms"`
	Workload      string `json:"workload"`
}

// ReliabilityReqs defines reliability requirements
type ReliabilityReqs struct {
	MinAvailability float64 `json:"min_availability"` // 99.9, 99.99, etc.
	DataCopies      int     `json:"data_copies"`
	GeoRedundancy   bool    `json:"geo_redundancy"`
	BackupFrequency string  `json:"backup_frequency"`
}

// BudgetConstraint defines budget constraints
type BudgetConstraint struct {
	MaxCostPerMonth float64 `json:"max_cost_per_month"`
	MaxCostPerGB    float64 `json:"max_cost_per_gb"`
}

// MigrationOptions for storage migration
type MigrationOptions struct {
	ThrottleMBps    int64    `json:"throttle_mbps"`
	VerifyChecksum  bool     `json:"verify_checksum"`
	DeleteSource    bool     `json:"delete_source"`
	SyncMode        string   `json:"sync_mode"` // full, incremental
	ExcludePatterns []string `json:"exclude_patterns"`
}

// OptimizationReport provides storage optimization recommendations
type OptimizationReport struct {
	GeneratedAt     time.Time         `json:"generated_at"`
	TotalSavings    int64             `json:"total_savings_bytes"`
	Recommendations []OptimizationRec `json:"recommendations"`
	CurrentCost     float64           `json:"current_cost"`
	OptimizedCost   float64           `json:"optimized_cost"`
}

// OptimizationRec represents an optimization recommendation
type OptimizationRec struct {
	VolumeID    string `json:"volume_id"`
	Type        string `json:"type"` // compress, dedupe, tier, resize
	Description string `json:"description"`
	Savings     int64  `json:"savings_bytes"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"` // low, medium, high
}

// DRPlan represents a disaster recovery plan
type DRPlan struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	PrimaryLocation string        `json:"primary_location"`
	DRLocation      string        `json:"dr_location"`
	RPO             time.Duration `json:"rpo"` // Recovery Point Objective
	RTO             time.Duration `json:"rto"` // Recovery Time Objective
	Volumes         []DRVolume    `json:"volumes"`
	TestSchedule    string        `json:"test_schedule"`
	LastTested      *time.Time    `json:"last_tested"`
	CreatedAt       time.Time     `json:"created_at"`
}

// DRVolume represents a volume in a DR plan
type DRVolume struct {
	VolumeID        string     `json:"volume_id"`
	ReplicationMode string     `json:"replication_mode"` // sync, async
	Priority        int        `json:"priority"`
	LastReplicated  *time.Time `json:"last_replicated"`
}

// ValidationRule defines a validation rule
type ValidationRule struct {
	Name    string      `json:"name"`
	Field   string      `json:"field"`
	Type    string      `json:"type"` // required, min, max, pattern, etc.
	Value   interface{} `json:"value"`
	Message string      `json:"message"`
}

// SystemInfo provides system information for compatibility checks
type SystemInfo struct {
	OS           string   `json:"os"`
	Kernel       string   `json:"kernel"`
	Architecture string   `json:"architecture"`
	TotalMemory  int64    `json:"total_memory"`
	TotalCPUs    int      `json:"total_cpus"`
	Features     []string `json:"features"`
}
