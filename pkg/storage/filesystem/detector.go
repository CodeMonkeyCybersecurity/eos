// pkg/storage/filesystem/detector.go

package filesystem

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Filesystem represents a filesystem type
type Filesystem string

const (
	Ext4   Filesystem = "ext4"
	XFS    Filesystem = "xfs"
	BTRFS  Filesystem = "btrfs"
	ZFS    Filesystem = "zfs"
	CephFS Filesystem = "ceph"
	NFS    Filesystem = "nfs"
	NTFS   Filesystem = "ntfs"
)

// Detector detects filesystem types and provides recommendations
type Detector struct {
	rc *eos_io.RuntimeContext
}

// NewDetector creates a new filesystem detector
func NewDetector(rc *eos_io.RuntimeContext) *Detector {
	return &Detector{rc: rc}
}

// Detect determines the filesystem type for a given path
func (d *Detector) Detect(path string) (Filesystem, error) {
	logger := otelzap.Ctx(d.rc.Ctx)
	
	output, err := execute.Run(d.rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-T", path},
		Capture: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to run df: %w", err)
	}
	
	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("unexpected df output")
	}
	
	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected df output format")
	}
	
	fs := Filesystem(strings.ToLower(fields[1]))
	logger.Debug("Detected filesystem",
		zap.String("path", path),
		zap.String("filesystem", string(fs)))
	
	return fs, nil
}

// RecommendForWorkload recommends a filesystem based on workload type
func (d *Detector) RecommendForWorkload(workload string) Filesystem {
	logger := otelzap.Ctx(d.rc.Ctx)
	
	recommendations := map[string]Filesystem{
		"database":         XFS,      // Better for large files and parallel I/O
		"container":        Ext4,     // Good general purpose, wide support
		"backup":           BTRFS,    // Snapshots and compression
		"distributed":      CephFS,   // Distributed storage
		"media":            XFS,      // Good for large media files
		"general":          Ext4,     // Safe default
		"high-performance": XFS,      // Better performance characteristics
		"snapshots":        BTRFS,    // Native snapshot support
	}
	
	recommended := Ext4 // Default
	if fs, ok := recommendations[strings.ToLower(workload)]; ok {
		recommended = fs
	}
	
	logger.Info("Filesystem recommendation",
		zap.String("workload", workload),
		zap.String("recommended", string(recommended)))
	
	return recommended
}

// GetFeatures returns the features of a filesystem
func (d *Detector) GetFeatures(fs Filesystem) []string {
	features := map[Filesystem][]string{
		Ext4: {
			"Journaling",
			"Extended attributes",
			"Large file support",
			"Online defragmentation",
			"Stable and mature",
		},
		XFS: {
			"High performance",
			"Parallel I/O",
			"Online defragmentation",
			"Scalable to large filesystems",
			"Efficient space allocation",
		},
		BTRFS: {
			"Copy-on-write",
			"Built-in compression",
			"Snapshots",
			"RAID support",
			"Online filesystem check",
		},
		ZFS: {
			"Copy-on-write",
			"Data integrity verification",
			"Snapshots and clones",
			"Built-in compression",
			"Deduplication",
		},
		CephFS: {
			"Distributed storage",
			"High availability",
			"Scalable performance",
			"POSIX compliant",
			"Snapshots",
		},
	}
	
	if f, ok := features[fs]; ok {
		return f
	}
	return []string{"Unknown filesystem"}
}

// CheckSupport verifies if a filesystem is supported on the system
func (d *Detector) CheckSupport(fs Filesystem) (bool, error) {
	logger := otelzap.Ctx(d.rc.Ctx)
	
	// Check if filesystem module is available
	moduleName := string(fs)
	
	// Check /proc/filesystems
	output, err := execute.Run(d.rc.Ctx, execute.Options{
		Command: "grep",
		Args:    []string{"-w", moduleName, "/proc/filesystems"},
		Capture: true,
	})
	if err == nil && strings.Contains(output, moduleName) {
		logger.Debug("Filesystem supported",
			zap.String("filesystem", moduleName))
		return true, nil
	}
	
	// Check if module can be loaded
	if _, err := execute.Run(d.rc.Ctx, execute.Options{
		Command: "modprobe",
		Args:    []string{"-n", moduleName},
		Capture: true,
	}); err == nil {
		logger.Debug("Filesystem module available",
			zap.String("filesystem", moduleName))
		return true, nil
	}
	
	logger.Debug("Filesystem not supported",
		zap.String("filesystem", moduleName))
	return false, nil
}

// GetOptimizationOptions returns optimization options for a filesystem
func (d *Detector) GetOptimizationOptions(fs Filesystem, workload string) map[string]string {
	options := make(map[string]string)
	
	switch fs {
	case Ext4:
		options["mount_options"] = "noatime,nodiratime"
		if workload == "database" {
			options["mount_options"] += ",data=writeback,barrier=0"
			options["tune2fs"] = "-o journal_data_writeback"
		}
		
	case XFS:
		options["mount_options"] = "noatime,nodiratime,nobarrier"
		if workload == "database" {
			options["mount_options"] += ",logbufs=8,logbsize=256k"
		}
		
	case BTRFS:
		options["mount_options"] = "noatime,compress=zstd"
		if workload == "backup" {
			options["mount_options"] += ",space_cache=v2"
		}
		
	case ZFS:
		options["properties"] = "compression=lz4,atime=off"
		if workload == "database" {
			options["properties"] += ",recordsize=16k,logbias=throughput"
		}
	}
	
	return options
}