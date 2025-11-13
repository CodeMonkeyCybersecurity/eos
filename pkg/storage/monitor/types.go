package monitor

import (
	"time"
)

// DiskUsage represents disk usage information
type DiskUsage struct {
	Path              string
	TotalSize         int64
	UsedSize          int64
	AvailableSize     int64
	UsedPercent       float64
	InodesTotal       uint64
	InodesUsed        uint64
	InodesFree        uint64
	InodesUsedPercent float64
	Device            string
	Filesystem        string
	MountOptions      []string
	Timestamp         time.Time
}

// IOMetrics represents I/O performance metrics
type IOMetrics struct {
	Device           string
	ReadOps          uint64
	WriteOps         uint64
	ReadBytes        uint64
	WriteBytes       uint64
	ReadTime         uint64
	WriteTime        uint64
	IOTime           uint64
	WeightedIOTime   uint64
	ReadBytesPerSec  float64
	WriteBytesPerSec float64
	ReadOpsPerSec    float64
	WriteOpsPerSec   float64
	AvgReadLatency   float64
	AvgWriteLatency  float64
	Utilization      float64
	Timestamp        time.Time
}

// MountInfo represents mount point information
type MountInfo struct {
	Device     string
	MountPoint string
	Filesystem string
	Options    []string
	DumpFreq   int
	PassNumber int
	Timestamp  time.Time
}

// SMARTData represents disk health information
type SMARTData struct {
	Device          string
	Model           string
	SerialNumber    string
	Capacity        int64
	PowerOnHours    uint64
	PowerCycleCount uint64
	Temperature     int
	HealthStatus    string
	Attributes      []SMARTAttribute
	OverallHealth   string
	Timestamp       time.Time
}

// SMARTAttribute represents individual SMART attributes
type SMARTAttribute struct {
	ID         int
	Name       string
	Value      int
	Worst      int
	Threshold  int
	Type       string
	Updated    string
	WhenFailed string
	RawValue   string
}

// PartitionInfo represents disk partition information
type PartitionInfo struct {
	Device     string
	Number     int
	Start      uint64
	End        uint64
	Size       uint64
	Type       string
	Filesystem string
	Label      string
	UUID       string
	Flags      []string
	Timestamp  time.Time
}

// DiskCleanupResult represents cleanup operation results
type DiskCleanupResult struct {
	Path         string
	InitialSize  int64
	FinalSize    int64
	FreedBytes   int64
	FilesRemoved int
	DirsRemoved  int
	Errors       []string
	Duration     time.Duration
	Timestamp    time.Time
}

// GrowthMetrics represents storage growth tracking
type GrowthMetrics struct {
	Path          string
	CurrentSize   int64
	PreviousSize  int64
	GrowthBytes   int64
	GrowthPercent float64
	GrowthRate    float64 // bytes per hour
	TimeWindow    time.Duration
	ProjectedFull time.Time
	DaysUntilFull float64
}

// ContentionMetrics represents resource contention indicators
type ContentionMetrics struct {
	Device          string
	IOWaitPercent   float64
	QueueDepth      float64
	ServiceTime     float64
	Utilization     float64
	ContentionScore float64 // 0-100 score
	Timestamp       time.Time
}

// Alert represents a storage alert
type Alert struct {
	ID         string
	Type       AlertType
	Severity   AlertSeverity
	Path       string
	Device     string
	Message    string
	Value      float64
	Threshold  float64
	Timestamp  time.Time
	Resolved   bool
	ResolvedAt time.Time
}

// AlertType represents the type of storage alert
type AlertType string

const (
	AlertTypeDiskUsage     AlertType = "disk_usage"
	AlertTypeIOPerformance AlertType = "io_performance"
	AlertTypeGrowthRate    AlertType = "growth_rate"
	AlertTypeContention    AlertType = "contention"
	AlertTypeFilesystem    AlertType = "filesystem"
)

// AlertSeverity represents alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityCritical AlertSeverity = "critical"
)

// MonitorConfig represents monitoring configuration
type MonitorConfig struct {
	// Thresholds
	DiskUsageWarning  float64 // Default: 70%
	DiskUsageCritical float64 // Default: 80%
	GrowthRateWarning float64 // GB per day
	IOLatencyWarning  float64 // milliseconds
	ContentionWarning float64 // Score 0-100

	// Monitoring intervals
	CheckInterval    time.Duration
	MetricsRetention time.Duration

	// Paths to monitor
	MonitorPaths       []string
	ExcludePaths       []string
	ExcludeFilesystems []string

	// Features
	EnableGrowthTracking bool
	EnableIOMetrics      bool
	EnableContention     bool
	EnableAutoCleanup    bool
}

// CleanupConfig represents automatic cleanup configuration
type CleanupConfig struct {
	Enabled         bool
	TriggerPercent  float64 // Trigger cleanup at this usage
	TargetPercent   float64 // Clean up to this usage
	MaxAge          time.Duration
	CleanupPaths    []string
	ExcludePatterns []string
	DryRun          bool
}

// HistoricalData represents historical metrics for trending
type HistoricalData struct {
	Path        string
	Metrics     []DiskUsage
	IOMetrics   []IOMetrics
	StartTime   time.Time
	EndTime     time.Time
	SampleCount int
}

const (
	// Default thresholds
	DefaultWarningThreshold  = 70.0
	DefaultCriticalThreshold = 80.0

	// Default intervals
	DefaultCheckInterval    = 5 * time.Minute
	DefaultMetricsRetention = 7 * 24 * time.Hour

	// Size units
	KB = 1024
	MB = KB * 1024
	GB = MB * 1024
	TB = GB * 1024
)

// StorageReport represents a comprehensive storage report
type StorageReport struct {
	Timestamp       time.Time
	SystemSummary   SystemSummary
	VolumeReports   []VolumeReport
	Alerts          []Alert
	Recommendations []string
}

// SystemSummary represents overall system storage status
type SystemSummary struct {
	TotalStorage     int64
	UsedStorage      int64
	AvailableStorage int64
	UsagePercent     float64
	VolumeCount      int
	AlertCount       int
	HealthScore      float64 // 0-100
}

// VolumeReport represents detailed report for a single volume
type VolumeReport struct {
	Path           string
	Device         string
	Filesystem     string
	Usage          DiskUsage
	Growth         GrowthMetrics
	Performance    IOMetrics
	Contention     ContentionMetrics
	TopDirectories []DirectoryInfo
	LargeFiles     []FileInfo
}

// DirectoryInfo represents directory size information
type DirectoryInfo struct {
	Path         string
	Size         int64
	FileCount    int
	ModifiedTime time.Time
}

// FileInfo represents file information
type FileInfo struct {
	Path         string
	Size         int64
	ModifiedTime time.Time
	AccessTime   time.Time
}
