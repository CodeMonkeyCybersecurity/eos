package docker_volume

import (
	"time"
)

// Config represents Docker volume configuration
type Config struct {
	Name       string
	Driver     string
	DriverOpts map[string]string
	Labels     map[string]string
	MountPoint string
	Scope      string
}

// VolumeInfo represents detailed volume information
type VolumeInfo struct {
	Name       string
	Driver     string
	Mountpoint string
	CreatedAt  time.Time
	Status     map[string]interface{}
	Labels     map[string]string
	Scope      string
	Options    map[string]string
	UsageData  *UsageData
	RefCount   int
}

// UsageData represents volume usage statistics
type UsageData struct {
	Size      int64
	RefCount  int
	SizeHuman string
}

// ContainerLogConfig represents container logging configuration
type ContainerLogConfig struct {
	ContainerID   string
	ContainerName string
	MaxSize       string // e.g., "100m"
	MaxFiles      int    // e.g., 3
	Driver        string // json-file, syslog, etc.
}

// PruneConfig represents volume pruning configuration
type PruneConfig struct {
	All         bool
	Force       bool
	Filter      []string
	KeepVolumes []string
	DryRun      bool
}

// BindMount represents a bind mount configuration
type BindMount struct {
	Source      string
	Target      string
	Type        string // bind or volume
	ReadOnly    bool
	Consistency string // default, consistent, cached, delegated
	Options     []string
}

// LogRotationStats represents log rotation statistics
type LogRotationStats struct {
	ContainerID    string
	ContainerName  string
	CurrentLogSize int64
	RotatedLogs    int
	TotalLogSize   int64
	LastRotation   time.Time
}

// VolumeBackupConfig represents volume backup configuration
type VolumeBackupConfig struct {
	VolumeName      string
	BackupPath      string
	Compression     bool
	ExcludePatterns []string
	IncludePatterns []string
}

const (
	// Default values
	DefaultMaxLogSize  = "100m"
	DefaultMaxLogFiles = 3
	DefaultLogDriver   = "json-file"

	// Volume drivers
	DriverLocal   = "local"
	DriverNFS     = "nfs"
	DriverOverlay = "overlay"

	// Size units
	Kilobyte = 1024
	Megabyte = 1024 * 1024
	Gigabyte = 1024 * 1024 * 1024
)

// LogDriverOptions provides recommended logging configurations
var LogDriverOptions = map[string]map[string]string{
	"production": {
		"max-size": "100m",
		"max-file": "3",
		"compress": "true",
		"labels":   "service,version,environment",
	},
	"development": {
		"max-size": "10m",
		"max-file": "1",
	},
	"high-volume": {
		"max-size": "200m",
		"max-file": "5",
		"compress": "true",
	},
}

// VolumeDriverOptions provides optimized driver options
var VolumeDriverOptions = map[string]map[string]string{
	"nfs": {
		"type":   "nfs",
		"o":      "addr=server,rw,nolock,hard,intr",
		"device": ":/path/to/share",
	},
	"tmpfs": {
		"type":   "tmpfs",
		"device": "tmpfs",
		"o":      "size=1g,mode=0755",
	},
	"bind": {
		"type":   "none",
		"o":      "bind",
		"device": "/host/path",
	},
}
