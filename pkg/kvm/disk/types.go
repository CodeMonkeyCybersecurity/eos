package disk

import (
	"time"
)

// Assessment contains the result of pre-flight disk analysis
type Assessment struct {
	VMName             string
	State              string // running, shut off, paused
	DiskPath           string
	CurrentSizeBytes   int64
	RequestedSizeBytes int64  // Absolute target size
	ChangeBytes        int64  // Positive=grow, negative=shrink
	Format             string // qcow2, raw, lvm
	GuestOS            string // linux, windows, unknown
	PartitionTable     string // gpt, mbr, unknown
	FilesystemType     string // xfs, ext4, btrfs, ntfs, unknown
	LVMDetected        bool
	EncryptionDetected bool
	HasSnapshots       bool
	SnapshotCount      int
	HasGuestAgent      bool
	GuestAgentVersion  string
	BackupExists       bool
	BackupAge          time.Duration
	BackupPath         string
	HostFreeSpaceBytes int64
	SafeToResize       bool
	Risks              []Risk
	RequiredActions    []string
}

// Risk represents a safety concern
type Risk struct {
	Level       RiskLevel // high, medium, low
	Description string
	Mitigation  string
}

// RiskLevel indicates severity
type RiskLevel string

const (
	RiskLevelHigh   RiskLevel = "high"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelLow    RiskLevel = "low"
)

// ResizeRequest contains parameters for a disk resize operation
type ResizeRequest struct {
	VMName     string
	SizeSpec   string // "+50G", "-10G", "200G"
	Force      bool
	DryRun     bool
	SkipBackup bool
	SkipVerify bool
	BackupPath string // Custom backup location
}

// Transaction represents a resize operation with rollback capability
type Transaction struct {
	ID          string
	VMName      string
	StartTime   time.Time
	EndTime     *time.Time
	ChangeBytes int64
	Steps       map[string]StepResult
	Success     bool
	Error       string
	BackupPath  string
}

// StepResult records the outcome of a transaction step
type StepResult struct {
	Name      string
	StartTime time.Time
	EndTime   time.Time
	Success   bool
	Error     string
	Data      map[string]interface{}
}

// SizeChange represents a parsed size specification
type SizeChange struct {
	IsAbsolute bool  // true for "200G", false for "+50G"
	IsGrowth   bool  // true for positive change
	Bytes      int64 // Absolute bytes to add/remove or target size
}
