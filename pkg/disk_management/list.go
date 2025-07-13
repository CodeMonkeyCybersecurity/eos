package disk_management

import (
	"fmt"
	"runtime"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListDisks lists all available disk devices following Assess → Intervene → Evaluate pattern
func ListDisks(rc *eos_io.RuntimeContext) (*DiskListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing disk listing requirements", zap.String("platform", runtime.GOOS))
	
	// Check platform support
	switch runtime.GOOS {
	case "darwin", "linux":
		// Supported platforms
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	
	// INTERVENE
	logger.Info("Listing disk devices")
	
	result := &DiskListResult{
		Disks:     make([]DiskInfo, 0),
		Timestamp: time.Now(),
	}
	
	var disks []DiskInfo
	var err error
	
	switch runtime.GOOS {
	case "darwin":
		disks, err = listDisksDarwin(rc)
		if err != nil {
			logger.Error("Failed to list disks on macOS", zap.Error(err))
			return nil, fmt.Errorf("failed to list disks on macOS: %w", err)
		}
	case "linux":
		disks, err = listDisksLinux(rc)
		if err != nil {
			logger.Error("Failed to list disks on Linux", zap.Error(err))
			return nil, fmt.Errorf("failed to list disks on Linux: %w", err)
		}
	}
	
	result.Disks = disks
	
	// EVALUATE
	logger.Info("Disk listing completed", 
		zap.Int("disk_count", len(result.Disks)),
		zap.Duration("duration", time.Since(result.Timestamp)))
	
	return result, nil
}

// ListPartitions lists partitions on a specific disk
func ListPartitions(rc *eos_io.RuntimeContext, diskPath string) (*PartitionListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing partition listing requirements", 
		zap.String("disk", diskPath),
		zap.String("platform", runtime.GOOS))
	
	if diskPath == "" {
		return nil, fmt.Errorf("disk path cannot be empty")
	}
	
	// INTERVENE
	logger.Info("Listing partitions", zap.String("disk", diskPath))
	
	result := &PartitionListResult{
		DiskPath:   diskPath,
		Partitions: make([]PartitionInfo, 0),
		Timestamp:  time.Now(),
	}
	
	var partitions []PartitionInfo
	var err error
	
	switch runtime.GOOS {
	case "darwin":
		partitions, err = listPartitionsDarwin(rc, diskPath)
		if err != nil {
			return nil, fmt.Errorf("failed to list partitions on macOS: %w", err)
		}
	case "linux":
		partitions, err = listPartitionsLinux(rc, diskPath)
		if err != nil {
			return nil, fmt.Errorf("failed to list partitions on Linux: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	
	result.Partitions = partitions
	
	// EVALUATE
	logger.Info("Partition listing completed",
		zap.String("disk", diskPath),
		zap.Int("partition_count", len(result.Partitions)))
	
	return result, nil
}

// GetMountedVolumes returns all currently mounted volumes
func GetMountedVolumes(rc *eos_io.RuntimeContext) ([]MountedVolume, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing mounted volumes")
	
	// INTERVENE
	switch runtime.GOOS {
	case "darwin":
		return getMountedVolumesDarwin(rc)
	case "linux":
		return getMountedVolumesLinux(rc)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}