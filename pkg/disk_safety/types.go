package disk_safety

import (
	"time"
)

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
	ID              string                 `json:"id"`
	StartTime       time.Time             `json:"start_time"`
	EndTime         *time.Time            `json:"end_time,omitempty"`
	OperationType   string                `json:"operation_type"`
	Target          DiskTarget            `json:"target"`
	Parameters      map[string]interface{} `json:"parameters"`
	PreState        *DiskState            `json:"pre_state"`
	PostState       *DiskState            `json:"post_state,omitempty"`
	Status          OperationStatus       `json:"status"`
	Commands        []ExecutedCommand     `json:"commands"`
	RollbackPlan    *RollbackPlan         `json:"rollback_plan,omitempty"`
	Snapshot        *Snapshot             `json:"snapshot,omitempty"`
	Error           string                `json:"error,omitempty"`
	User            string                `json:"user"`
	Checksum        string                `json:"checksum"`
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
	Timestamp   time.Time              `json:"timestamp"`
	LVMState    *LVMState              `json:"lvm_state,omitempty"`
	Filesystems []FilesystemState      `json:"filesystems"`
	Mounts      []MountState           `json:"mounts"`
	BlockDevs   map[string]BlockDevice `json:"block_devices"`
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
	Device    string `json:"device"`
	Size      int64  `json:"size"`
	Free      int64  `json:"free"`
	VGName    string `json:"vg_name"`
	UUID      string `json:"uuid"`
	Allocatable bool `json:"allocatable"`
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
	Name        string `json:"name"`
	VGName      string `json:"vg_name"`
	UUID        string `json:"uuid"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	Active      bool   `json:"active"`
	Open        bool   `json:"open"`
	Attributes  string `json:"attributes"`
	DevicePath  string `json:"device_path"`
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

// BlockDevice represents block device information
type BlockDevice struct {
	Name       string                `json:"name"`
	Size       int64                 `json:"size"`
	Type       string                `json:"type"`
	Mountpoint string                `json:"mountpoint,omitempty"`
	UUID       string                `json:"uuid,omitempty"`
	Label      string                `json:"label,omitempty"`
	Model      string                `json:"model,omitempty"`
	Serial     string                `json:"serial,omitempty"`
	Children   []BlockDevice         `json:"children,omitempty"`
	ReadOnly   bool                  `json:"readonly"`
	Removable  bool                  `json:"removable"`
	Rotational bool                  `json:"rotational"`
	SSDInfo    *SSDInfo              `json:"ssd_info,omitempty"`
}

// SSDInfo contains SSD-specific information
type SSDInfo struct {
	WearLevel    int    `json:"wear_level"`
	LifetimeUsed int    `json:"lifetime_used"`
	Model        string `json:"model"`
}

// DiskUsageState represents disk usage at a point in time
type DiskUsageState struct {
	Filesystem  string  `json:"filesystem"`
	Size        int64   `json:"size"`
	Used        int64   `json:"used"`
	Available   int64   `json:"available"`
	UsePercent  float64 `json:"use_percent"`
	Mountpoint  string  `json:"mountpoint"`
}

// ExecutedCommand represents a command that was executed
type ExecutedCommand struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	Args      []string  `json:"args"`
	WorkDir   string    `json:"work_dir,omitempty"`
	Output    string    `json:"output"`
	Error     string    `json:"error,omitempty"`
	ExitCode  int       `json:"exit_code"`
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
	Name      string    `json:"name"`
	SourceVG  string    `json:"source_vg"`
	SourceLV  string    `json:"source_lv"`
	Size      int64     `json:"size"`
	Created   time.Time `json:"created"`
	JournalID string    `json:"journal_id"`
	AutoRemove bool     `json:"auto_remove"`
	RemoveAt  *time.Time `json:"remove_at,omitempty"`
}

// PreflightReport contains results of preflight checks
type PreflightReport struct {
	Target      DiskTarget    `json:"target"`
	Timestamp   time.Time     `json:"timestamp"`
	Checks      []CheckResult `json:"checks"`
	OverallPass bool          `json:"overall_pass"`
	Warnings    []string      `json:"warnings"`
	Errors      []string      `json:"errors"`
}

// CheckResult represents the result of a single check
type CheckResult struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Severity    CheckSeverity `json:"severity"`
	Passed      bool          `json:"passed"`
	Message     string        `json:"message,omitempty"`
	Error       string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
}

// CheckSeverity indicates how critical a check is
type CheckSeverity string

const (
	SeverityInfo     CheckSeverity = "info"
	SeverityWarning  CheckSeverity = "warning"
	SeverityCritical CheckSeverity = "critical"
)

// ExpandRequest represents a disk expansion request
type ExpandRequest struct {
	VolumeGroup      string            `json:"volume_group"`
	LogicalVolume    string            `json:"logical_volume"`
	Size             string            `json:"size"`
	ResizeFilesystem bool              `json:"resize_filesystem"`
	Force            bool              `json:"force"`
	AllowNoSnapshot  bool              `json:"allow_no_snapshot"`
	DryRun           bool              `json:"dry_run"`
	Metadata         map[string]string `json:"metadata"`
}

// ExpandPreview shows what would happen in an expansion
type ExpandPreview struct {
	CurrentSize      int64             `json:"current_size"`
	RequestedSize    int64             `json:"requested_size"`
	ActualNewSize    int64             `json:"actual_new_size"`
	FilesystemSize   int64             `json:"filesystem_size"`
	AvailableSpace   int64             `json:"available_space"`
	Commands         []PreviewCommand  `json:"commands"`
	EstimatedDuration time.Duration    `json:"estimated_duration"`
	Warnings         []string          `json:"warnings"`
	RequiresUnmount  bool              `json:"requires_unmount"`
}

// PreviewCommand shows a command that would be executed
type PreviewCommand struct {
	Command     string `json:"command"`
	Args        []string `json:"args"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

// DiskInspection represents comprehensive disk inspection data
type DiskInspection struct {
	Timestamp       time.Time         `json:"timestamp"`
	SystemOverview  SystemDiskOverview `json:"system_overview"`
	PhysicalDisks   []PhysicalDisk    `json:"physical_disks"`
	LVMHierarchy    *LVMHierarchy     `json:"lvm_hierarchy,omitempty"`
	Filesystems     []FilesystemInfo  `json:"filesystems"`
	Recommendations []Recommendation  `json:"recommendations"`
	Alerts          []DiskAlert       `json:"alerts"`
}

// SystemDiskOverview provides high-level disk statistics
type SystemDiskOverview struct {
	TotalDisks       int   `json:"total_disks"`
	TotalCapacity    int64 `json:"total_capacity"`
	UsedCapacity     int64 `json:"used_capacity"`
	FreeCapacity     int64 `json:"free_capacity"`
	UnallocatedDisks int   `json:"unallocated_disks"`
	HealthyDisks     int   `json:"healthy_disks"`
	WarningDisks     int   `json:"warning_disks"`
	FailingDisks     int   `json:"failing_disks"`
}

// PhysicalDisk represents a physical disk device
type PhysicalDisk struct {
	Device       string            `json:"device"`
	Model        string            `json:"model"`
	Serial       string            `json:"serial"`
	Size         int64             `json:"size"`
	Type         string            `json:"type"`
	Interface    string            `json:"interface"`
	SmartStatus  string            `json:"smart_status"`
	Temperature  int               `json:"temperature"`
	PowerOnHours int               `json:"power_on_hours"`
	Partitions   []Partition       `json:"partitions"`
	InUse        bool              `json:"in_use"`
	UsageType    string            `json:"usage_type"`
}

// Partition represents a disk partition
type Partition struct {
	Device     string `json:"device"`
	Number     int    `json:"number"`
	Start      int64  `json:"start"`
	End        int64  `json:"end"`
	Size       int64  `json:"size"`
	Type       string `json:"type"`
	Filesystem string `json:"filesystem,omitempty"`
	Label      string `json:"label,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Flags      []string `json:"flags,omitempty"`
}

// LVMHierarchy represents the complete LVM structure
type LVMHierarchy struct {
	PhysicalVolumes []PVInfo `json:"physical_volumes"`
	VolumeGroups    []VGInfo `json:"volume_groups"`
	LogicalVolumes  []LVInfo `json:"logical_volumes"`
	Relationships   []LVMRelation `json:"relationships"`
}

// PVInfo represents physical volume information
type PVInfo struct {
	Device      string `json:"device"`
	VGName      string `json:"vg_name"`
	Size        int64  `json:"size"`
	Free        int64  `json:"free"`
	Used        int64  `json:"used"`
	UUID        string `json:"uuid"`
	Allocatable bool   `json:"allocatable"`
}

// VGInfo represents volume group information
type VGInfo struct {
	Name        string   `json:"name"`
	UUID        string   `json:"uuid"`
	Size        int64    `json:"size"`
	Free        int64    `json:"free"`
	Used        int64    `json:"used"`
	PVCount     int      `json:"pv_count"`
	LVCount     int      `json:"lv_count"`
	PVs         []string `json:"pvs"`
	ExtentSize  int64    `json:"extent_size"`
	TotalExtents int     `json:"total_extents"`
	FreeExtents  int     `json:"free_extents"`
}

// LVInfo represents logical volume information
type LVInfo struct {
	Name       string `json:"name"`
	VGName     string `json:"vg_name"`
	UUID       string `json:"uuid"`
	Size       int64  `json:"size"`
	Path       string `json:"path"`
	Active     bool   `json:"active"`
	Filesystem string `json:"filesystem,omitempty"`
	Mountpoint string `json:"mountpoint,omitempty"`
	UsePercent float64 `json:"use_percent,omitempty"`
}

// LVMRelation describes relationships in LVM
type LVMRelation struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	Target string `json:"target"`
}

// FilesystemInfo represents filesystem details
type FilesystemInfo struct {
	Device      string  `json:"device"`
	Type        string  `json:"type"`
	Mountpoint  string  `json:"mountpoint"`
	TotalSize   int64   `json:"total_size"`
	UsedSize    int64   `json:"used_size"`
	FreeSize    int64   `json:"free_size"`
	UsePercent  float64 `json:"use_percent"`
	InodesTotal int64   `json:"inodes_total"`
	InodesUsed  int64   `json:"inodes_used"`
	InodesFree  int64   `json:"inodes_free"`
	ReadOnly    bool    `json:"readonly"`
	Options     []string `json:"options"`
}

// Recommendation suggests disk optimizations
type Recommendation struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Command     string `json:"command,omitempty"`
	Impact      string `json:"impact"`
}

// DiskAlert represents a disk-related alert
type DiskAlert struct {
	Level       string    `json:"level"`
	Type        string    `json:"type"`
	Device      string    `json:"device"`
	Message     string    `json:"message"`
	Details     string    `json:"details"`
	Timestamp   time.Time `json:"timestamp"`
}

// IOMetrics represents I/O performance metrics
type IOMetrics struct {
	Device          string  `json:"device"`
	ReadsPerSec     float64 `json:"reads_per_sec"`
	WritesPerSec    float64 `json:"writes_per_sec"`
	ReadBytesPerSec int64   `json:"read_bytes_per_sec"`
	WriteBytesPerSec int64  `json:"write_bytes_per_sec"`
	AvgQueueSize    float64 `json:"avg_queue_size"`
	AvgWaitTime     float64 `json:"avg_wait_time"`
	Utilization     float64 `json:"utilization"`
}

// SafetyConfig contains safety settings for disk operations
type SafetyConfig struct {
	RequireSnapshot      bool          `json:"require_snapshot"`
	SnapshotMinSize      int64         `json:"snapshot_min_size"`
	SnapshotMaxSize      int64         `json:"snapshot_max_size"`
	SnapshotRetention    time.Duration `json:"snapshot_retention"`
	RequireBackup        bool          `json:"require_backup"`
	BackupMaxAge         time.Duration `json:"backup_max_age"`
	AllowOnlineResize    bool          `json:"allow_online_resize"`
	MaxResizePercent     int           `json:"max_resize_percent"`
	RequireHealthCheck   bool          `json:"require_health_check"`
	AutoCleanSnapshots   bool          `json:"auto_clean_snapshots"`
	JournalRetention     time.Duration `json:"journal_retention"`
}

// Constants for disk operations
const (
	JournalDir = "/var/lib/eos/disk-operations"
	ActiveDir  = "active"
	ArchiveDir = "archive"
	
	DefaultSnapshotMinSize = 1 << 30  // 1GB
	DefaultSnapshotMaxSize = 50 << 30 // 50GB
	DefaultSnapshotKeepTime = 24 * time.Hour // 24 hours
	DefaultSnapshotRetention = 24 * time.Hour
	DefaultJournalRetention = 90 * 24 * time.Hour
	
	MaxResizeAttempts = 3
	ResizeRetryDelay = 5 * time.Second
)