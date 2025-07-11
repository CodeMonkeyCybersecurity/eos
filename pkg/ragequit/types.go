package ragequit

import "time"

// Config holds configuration for ragequit operations
type Config struct {
	Reason            string
	NoReboot          bool
	Force             bool
	Actions           string
	SkipValidation    bool
	BackupGracePeriod time.Duration
	ShutdownTimeout   time.Duration
	NotificationWait  time.Duration
	DiagnosticsDir    string
}

// DefaultConfig returns default ragequit configuration
func DefaultConfig() *Config {
	return &Config{
		Actions:           "all",
		BackupGracePeriod: 30 * time.Second,
		ShutdownTimeout:   60 * time.Second,
		NotificationWait:  10 * time.Second,
		DiagnosticsDir:    "/var/log/eos-ragequit",
	}
}

// EnvironmentInfo holds detected environment information
type EnvironmentInfo struct {
	Type          string // Docker, Kubernetes, BareMetal, VM
	CloudProvider string // AWS, GCP, Azure, None
	Metadata      map[string]string
}

// ResourceInfo holds system resource information
type ResourceInfo struct {
	DiskUsage   map[string]DiskInfo
	MemoryUsage MemoryInfo
	CPUUsage    float64
	LoadAverage [3]float64
}

// DiskInfo holds disk usage information
type DiskInfo struct {
	Total     uint64
	Used      uint64
	Available uint64
	Percent   float64
}

// MemoryInfo holds memory usage information
type MemoryInfo struct {
	Total       uint64
	Used        uint64
	Available   uint64
	SwapTotal   uint64
	SwapUsed    uint64
	SwapPercent float64
}