package disk_management

import (
	"time"
)

// DiskInfo represents information about a disk device
type DiskInfo struct {
	Device      string            `json:"device"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Size        int64             `json:"size"`
	SizeHuman   string            `json:"size_human"`
	IsRemovable bool              `json:"is_removable"`
	IsUSB       bool              `json:"is_usb"`
	Vendor      string            `json:"vendor"`
	Model       string            `json:"model"`
	Serial      string            `json:"serial"`
	Mountpoints []MountPoint      `json:"mountpoints"`
	Partitions  []PartitionInfo   `json:"partitions"`
	Properties  map[string]string `json:"properties"`
}

// MountPoint represents a mount point
type MountPoint struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

// PartitionInfo represents information about a partition
type PartitionInfo struct {
	Device     string `json:"device"`
	Number     int    `json:"number"`
	Size       int64  `json:"size"`
	SizeHuman  string `json:"size_human"`
	Type       string `json:"type"`
	Filesystem string `json:"filesystem"`
	Label      string `json:"label"`
	UUID       string `json:"uuid"`
	IsMounted  bool   `json:"is_mounted"`
	MountPoint string `json:"mount_point"`
}

// DiskListResult contains results of listing disks
type DiskListResult struct {
	Disks     []DiskInfo `json:"disks"`
	Total     int        `json:"total"`
	Timestamp time.Time  `json:"timestamp"`
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
