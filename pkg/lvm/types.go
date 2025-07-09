package lvm

import (
	"time"
)

// PhysicalVolumeConfig represents configuration for creating a physical volume
type PhysicalVolumeConfig struct {
	Device        string
	Force         bool
	UUID          string
	DataAlignment string
	MetadataSize  string
}

// VolumeGroupConfig represents configuration for creating a volume group
type VolumeGroupConfig struct {
	Name               string
	PhysicalVolumes    []string
	ExtentSize         string
	MaxLogicalVolumes  int
	MaxPhysicalVolumes int
}

// LogicalVolumeConfig represents configuration for creating a logical volume
type LogicalVolumeConfig struct {
	Name         string
	VolumeGroup  string
	Size         string
	Type         string // linear, striped, mirror, raid, thin, cache
	FileSystem   string // ext4, xfs, btrfs
	MountPoint   string
	MountOptions []string
	Stripes      int
	StripeSize   string
	MirrorCount  int
	ThinPool     string
}

// SnapshotConfig represents configuration for creating snapshots
type SnapshotConfig struct {
	Name         string
	OriginVolume string
	VolumeGroup  string
	Size         string
	Thin         bool
}

// PhysicalVolume represents a physical volume
type PhysicalVolume struct {
	Device       string
	UUID         string
	Size         int64
	Free         int64
	Used         int64
	VolumeGroup  string
	Allocatable  bool
	ExtentSize   int64
	TotalExtents int64
	FreeExtents  int64
	Attributes   string
}

// VolumeGroup represents a volume group
type VolumeGroup struct {
	Name            string
	UUID            string
	Size            int64
	Free            int64
	Used            int64
	ExtentSize      int64
	TotalExtents    int64
	FreeExtents     int64
	PhysicalVolumes []string
	LogicalVolumes  []string
	SnapshotCount   int
	Attributes      string
}

// LogicalVolume represents a logical volume
type LogicalVolume struct {
	Name        string
	Path        string
	VolumeGroup string
	UUID        string
	Size        int64
	Origin      string
	SnapshotOf  string
	Type        string
	Attributes  string
	MountPoint  string
	FileSystem  string
	State       string
	OpenCount   int
	CurrentLE   int64
	Segments    int
	CreatedAt   time.Time
}

// FileSystemConfig represents filesystem-specific configuration
type FileSystemConfig struct {
	Type         string
	Label        string
	UUID         string
	BlockSize    int
	InodeSize    int
	Reserved     int // Reserved blocks percentage
	MountOptions []string

	// XFS-specific options
	XFSLogSize    string
	XFSLogDev     string
	XFSSectorSize int

	// EXT4-specific options
	EXT4JournalDev  string
	EXT4Stride      int
	EXT4StripeWidth int

	// Performance options for databases
	DatabaseOptimized bool
}

const (
	// Default values
	DefaultExtentSize        = "4M"
	DefaultThinPoolChunkSize = "64K"
	DefaultStripeSize        = "64K"

	// XFS optimal settings for databases
	XFSDefaultLogSize    = "256M"
	XFSDefaultSectorSize = 4096

	// Mount options for different use cases
	MountOptionNoatime    = "noatime"
	MountOptionNodiratime = "nodiratime"
	MountOptionNobarrier  = "nobarrier"
	MountOptionRelatime   = "relatime"
)

// XFSMountOptions provides optimized mount options for XFS
var XFSMountOptions = map[string][]string{
	"database": {
		"noatime",
		"nodiratime",
		"nobarrier",
		"logbufs=8",
		"logbsize=256k",
		"allocsize=16m",
	},
	"general": {
		"noatime",
		"nodiratime",
		"inode64",
		"allocsize=1m",
	},
}

// EXT4MountOptions provides optimized mount options for EXT4
var EXT4MountOptions = map[string][]string{
	"database": {
		"noatime",
		"nodiratime",
		"nobarrier",
		"data=writeback",
		"commit=60",
	},
	"general": {
		"noatime",
		"nodiratime",
		"errors=remount-ro",
		"commit=60",
	},
}
