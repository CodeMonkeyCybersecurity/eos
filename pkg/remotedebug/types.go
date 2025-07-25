package remotedebug

import (
	"time"
)

// Config holds the configuration for remote debugging
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	KeyPath  string
	SudoPass string
	Timeout  time.Duration
}

// OutputFormat defines the output format for results
type OutputFormat int

const (
	OutputHuman OutputFormat = iota
	OutputJSON
)

// DiagnosticOptions configures what diagnostics to run
type DiagnosticOptions struct {
	CheckType   string // all, disk, memory, network, auth
	KernelLogs  bool
	Since       string
}

// SystemInfo holds comprehensive system information
type SystemInfo struct {
	Hostname            string
	DiskUsage           []DiskInfo
	LargeFiles          []FileInfo
	LargeDirectories    map[string]int64
	ServiceHealth       map[string]bool
	LogSizes            map[string]int64
	JournalSize         int64
	DeletedButOpenFiles []FileInfo
	MemoryUsage         MemoryInfo
	ProcessInfo         []ProcessInfo
	NetworkInfo         NetworkInfo
}

// DiskInfo represents disk usage for a mount point
type DiskInfo struct {
	Mount         string
	Total         int64
	Used          int64
	Available     int64
	UsePercent    float64
	Inodes        int64
	InodesUsed    int64
	InodesPercent float64
}

// FileInfo represents information about a file
type FileInfo struct {
	Path    string
	Size    int64
	Process string
	PID     string
}

// MemoryInfo holds memory usage information
type MemoryInfo struct {
	Total       int64
	Available   int64
	Used        int64
	UsePercent  float64
	SwapTotal   int64
	SwapUsed    int64
	SwapPercent float64
}

// ProcessInfo holds information about a process
type ProcessInfo struct {
	PID         string
	User        string
	CPUPercent  float64
	MemPercent  float64
	Command     string
}

// NetworkInfo holds network-related information
type NetworkInfo struct {
	Connections      int
	ListeningPorts   []string
	EstablishedConns int
	TimeWaitConns    int
}

// SystemReport contains the complete diagnostic report
type SystemReport struct {
	Timestamp           time.Time
	Hostname            string
	DiskUsage           []DiskInfo
	LargeFiles          []FileInfo
	LargeDirectories    map[string]int64
	ServiceHealth       map[string]bool
	LogSizes            map[string]int64
	JournalSize         int64
	DeletedButOpenFiles []FileInfo
	MemoryUsage         MemoryInfo
	ProcessInfo         []ProcessInfo
	NetworkInfo         NetworkInfo
	KernelLogs          *KernelLogs
	Issues              []Issue
	Warnings            []Warning
	Summary             string
}

// Issue represents a detected problem
type Issue struct {
	Severity    string // critical, high, medium, low
	Category    string
	Description string
	Evidence    string
	Impact      string
	Remediation string
}

// Warning represents a potential problem
type Warning struct {
	Category    string
	Description string
	Suggestion  string
}

// FixReport contains results of automated fixes
type FixReport struct {
	StartTime          time.Time
	Duration           time.Duration
	Actions            []FixAction
	Success            bool
	Message            string
	VerificationReport *SystemReport // Post-fix verification results
}

// FixAction represents a single fix action taken
type FixAction struct {
	Name       string
	StartTime  time.Time
	Duration   time.Duration
	Success    bool
	Message    string
	SpaceFreed int64
}

// SSHHealthCheck result
type SSHHealthResult struct {
	Healthy      bool
	Issues       []Issue
	Warnings     []Warning
	Diagnostics  map[string]interface{}
}

// KernelLogs holds kernel log information
type KernelLogs struct {
	RetrievedAt time.Time
	Source      string
	Messages    []KernelMessage
}

// KernelMessage represents a single kernel log entry
type KernelMessage struct {
	Timestamp time.Time
	Level     string
	Category  string
	Message   string
	Raw       string
	Source    string
	Metadata  map[string]string
}

// KernelPanic represents a kernel panic event
type KernelPanic struct {
	Timestamp   time.Time
	Type        string
	Message     string
	CallTrace   []string
	LikelyCause string
}

// HardwareIssue represents a hardware problem
type HardwareIssue struct {
	Timestamp   time.Time
	Type        string
	Description string
	Message     string
	Severity    string
}

// PerformanceIssue represents a performance problem
type PerformanceIssue struct {
	Timestamp       time.Time
	Type            string
	Description     string
	Message         string
	AffectedProcess string
	Duration        string
}

// Constants for common issues
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	
	CategoryDisk     = "disk"
	CategoryMemory   = "memory"
	CategoryNetwork  = "network"
	CategoryAuth     = "authentication"
	CategorySSH      = "ssh"
	CategoryKernel   = "kernel"
	CategorySecurity = "security"
)

// Default timeouts and limits
const (
	DefaultSSHTimeout     = 30 * time.Second
	DefaultCommandTimeout = 2 * time.Minute
	MaxOutputSize         = 30000 // characters
	MaxRetries            = 3
)