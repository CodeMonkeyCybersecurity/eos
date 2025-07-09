package btrfs

import (
	"time"
)

// Config represents BTRFS volume configuration
type Config struct {
	Device       string
	Label        string
	UUID         string
	MountPoint   string
	MountOptions []string
	Force        bool

	// Subvolume configuration
	SubvolumeName string
	SubvolumePath string

	// Compression settings
	Compression      string // none, zlib, lzo, zstd
	CompressionLevel int    // 1-15 for zstd

	// Features
	MixedMode  bool
	Nodatasum  bool
	Nodatacow  bool
	DisableCoW bool
}

// VolumeInfo represents BTRFS volume information
type VolumeInfo struct {
	UUID        string
	Label       string
	TotalSize   int64
	UsedSize    int64
	DeviceCount int
	Devices     []string
	MountPoints []string
	Features    []string
	Generation  int64
	NodeSize    int
	SectorSize  int
	CreatedAt   time.Time
}

// SubvolumeInfo represents a BTRFS subvolume
type SubvolumeInfo struct {
	ID           int64
	Path         string
	ParentID     int64
	TopLevel     int64
	Generation   int64
	UUID         string
	ParentUUID   string
	ReceivedUUID string
	Flags        string
	SendTime     time.Time
	ReceiveTime  time.Time
	Snapshots    []string
}

// SnapshotConfig represents snapshot configuration
type SnapshotConfig struct {
	SourcePath   string
	SnapshotPath string
	Readonly     bool
	Recursive    bool
}

// CompressionStats represents compression statistics
type CompressionStats struct {
	Type             string
	Level            int
	UncompressedSize int64
	CompressedSize   int64
	CompressionRatio float64
	FilesCompressed  int64
	FilesTotal       int64
}

// UsageInfo represents BTRFS usage information
type UsageInfo struct {
	TotalSize       int64
	UsedSize        int64
	FreeSize        int64
	DataSize        int64
	MetadataSize    int64
	SystemSize      int64
	UnallocatedSize int64
}

// BalanceConfig represents balance operation configuration
type BalanceConfig struct {
	DataFilters     []string
	MetadataFilters []string
	SystemFilters   []string
	Force           bool
	Background      bool
}

// ScrubStatus represents scrub operation status
type ScrubStatus struct {
	Running             bool
	StartTime           time.Time
	Duration            time.Duration
	DataScrubbed        int64
	TreeScrubbed        int64
	DataExtents         int64
	TreeExtents         int64
	DataErrors          int64
	TreeErrors          int64
	CsumErrors          int64
	VerifyErrors        int64
	NoChecksumErrors    int64
	CsumDiscards        int64
	SuperErrors         int64
	MallocErrors        int64
	UncorrectableErrors int64
	CorrectableErrors   int64
	LastError           string
}

const (
	// Compression types
	CompressionNone = "none"
	CompressionZlib = "zlib"
	CompressionLZO  = "lzo"
	CompressionZSTD = "zstd"

	// Default compression settings for backups
	DefaultBackupCompression      = CompressionZSTD
	DefaultBackupCompressionLevel = 3

	// Mount option constants
	MountOptionCompress      = "compress"
	MountOptionCompressForce = "compress-force"
	MountOptionNoatime       = "noatime"
	MountOptionNodatacow     = "nodatacow"
	MountOptionNodatasum     = "nodatasum"
	MountOptionAutodefrag    = "autodefrag"
	MountOptionSpace_cache   = "space_cache=v2"
	MountOptionSSD           = "ssd"
	MountOptionDiscard       = "discard=async"
)

// MountOptions provides optimized mount options for different use cases
var MountOptions = map[string][]string{
	"backup": {
		"compress-force=zstd:3",
		"noatime",
		"space_cache=v2",
		"autodefrag",
	},
	"general": {
		"compress=zstd:1",
		"noatime",
		"space_cache=v2",
	},
	"database": {
		"nodatacow",
		"nodatasum",
		"noatime",
		"space_cache=v2",
	},
	"ssd": {
		"compress=zstd:1",
		"noatime",
		"space_cache=v2",
		"ssd",
		"discard=async",
	},
}

// Compr
