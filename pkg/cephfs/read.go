package cephfs

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReadVolumeInfo retrieves information about a CephFS volume
func ReadVolumeInfo(rc *eos_io.RuntimeContext, volumeName string) (*VolumeInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing CephFS volume for information retrieval",
		zap.String("volume", volumeName))

	// Check if ceph command is available
	if _, err := eos_cli.LookPath("ceph"); err != nil {
		return nil, eos_err.NewUserError("ceph command not found. Please install ceph-common package")
	}

	// INTERVENE - Gather volume information
	logger.Info("Reading CephFS volume information",
		zap.String("volume", volumeName))

	info := &VolumeInfo{
		Name: volumeName,
	}

	// Get filesystem status
	statusCmd := eos_cli.Wrap(rc, "ceph", "fs", "status", volumeName, "--format", "json")
	statusOutput, err := statusCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get volume status: %w", err)
	}

	// Parse status JSON
	var status map[string]interface{}
	if err := json.Unmarshal(statusOutput, &status); err != nil {
		logger.Warn("Failed to parse status JSON",
			zap.Error(err))
	} else {
		// Extract relevant information
		if state, ok := status["state"].(string); ok {
			info.State = state
		}

		// Get data pools
		if pools, ok := status["data_pools"].([]interface{}); ok {
			for _, pool := range pools {
				if poolName, ok := pool.(string); ok {
					info.DataPools = append(info.DataPools, poolName)
				}
			}
		}

		// Get metadata pools
		if pools, ok := status["metadata_pool"].(string); ok {
			info.MetadataPools = append(info.MetadataPools, pools)
		}
	}

	// Get volume statistics
	statsCmd := eos_cli.Wrap(rc, "ceph", "fs", "get", volumeName, "--format", "json")
	statsOutput, err := statsCmd.Output()
	if err != nil {
		logger.Warn("Failed to get volume statistics",
			zap.Error(err))
	} else {
		var stats map[string]interface{}
		if err := json.Unmarshal(statsOutput, &stats); err == nil {
			if id, ok := stats["id"].(float64); ok {
				info.ID = fmt.Sprintf("%d", int(id))
			}

			if created, ok := stats["created"].(string); ok {
				if t, err := time.Parse(time.RFC3339, created); err == nil {
					info.CreatedAt = t
				}
			}
		}
	}

	// Get disk usage
	if err := readDiskUsage(rc, volumeName, info); err != nil {
		logger.Warn("Failed to read disk usage",
			zap.Error(err))
	}

	// Get mount points
	if mounts, err := readMountPoints(rc, volumeName); err == nil {
		info.MountPoints = mounts
	}

	// EVALUATE
	logger.Info("Evaluating collected volume information")

	if info.State == "" {
		logger.Warn("Could not determine volume state")
		info.State = "unknown"
	}

	logger.Info("Successfully read CephFS volume information",
		zap.String("volume", volumeName),
		zap.String("state", info.State),
		zap.Int("dataPools", len(info.DataPools)))

	return info, nil
}

// ReadMountInfo retrieves information about CephFS mounts
func ReadMountInfo(rc *eos_io.RuntimeContext, mountPoint string) (*MountInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing mount point",
		zap.String("mountPoint", mountPoint))

	// INTERVENE
	logger.Info("Reading mount information")

	info := &MountInfo{
		MountPoint: mountPoint,
	}

	// Use findmnt to get detailed mount information
	findmntCmd := eos_cli.Wrap(rc, "findmnt", "-J", "-T", mountPoint)
	output, err := findmntCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("mount point not found: %w", err)
	}

	// Parse findmnt JSON output
	var result struct {
		Filesystems []struct {
			Target  string `json:"target"`
			Source  string `json:"source"`
			Fstype  string `json:"fstype"`
			Options string `json:"options"`
		} `json:"filesystems"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse mount information: %w", err)
	}

	if len(result.Filesystems) == 0 {
		return nil, fmt.Errorf("no filesystem found at mount point")
	}

	fs := result.Filesystems[0]
	info.Device = fs.Source
	info.FileSystem = fs.Fstype
	info.Options = strings.Split(fs.Options, ",")
	info.IsActive = true

	// Check if it's actually a CephFS mount
	if info.FileSystem != "ceph" {
		return nil, eos_err.NewUserError("mount point %s is not a CephFS mount (filesystem: %s)",
			mountPoint, info.FileSystem)
	}

	// EVALUATE
	logger.Info("Mount information retrieved successfully",
		zap.String("device", info.Device),
		zap.String("filesystem", info.FileSystem),
		zap.Int("options", len(info.Options)))

	return info, nil
}

// ReadPerformanceMetrics reads CephFS performance metrics
func ReadPerformanceMetrics(rc *eos_io.RuntimeContext, volumeName string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing CephFS for performance metrics",
		zap.String("volume", volumeName))

	// INTERVENE
	logger.Info("Collecting performance metrics")

	metrics := make(map[string]interface{})

	// Get MDS performance stats
	mdsCmd := eos_cli.Wrap(rc, "ceph", "fs", "perf", "stats", volumeName, "--format", "json")
	if output, err := mdsCmd.Output(); err == nil {
		var perfStats map[string]interface{}
		if err := json.Unmarshal(output, &perfStats); err == nil {
			metrics["mds_performance"] = perfStats
		}
	}

	// Get client I/O stats
	clientCmd := eos_cli.Wrap(rc, "ceph", "fs", "status", volumeName, "--format", "json")
	if output, err := clientCmd.Output(); err == nil {
		var status map[string]interface{}
		if err := json.Unmarshal(output, &status); err == nil {
			if clients, ok := status["clients"].([]interface{}); ok {
				metrics["client_count"] = len(clients)
				metrics["clients"] = clients
			}
		}
	}

	// Get pool statistics for the volume's pools
	if pools, err := getVolumePools(rc, volumeName); err == nil {
		poolStats := make(map[string]interface{})
		for _, pool := range pools {
			if stats, err := getPoolStats(rc, pool); err == nil {
				poolStats[pool] = stats
			}
		}
		metrics["pool_stats"] = poolStats
	}

	// EVALUATE
	logger.Info("Performance metrics collected",
		zap.Int("metricTypes", len(metrics)))

	return metrics, nil
}

// Helper functions

func readDiskUsage(rc *eos_io.RuntimeContext, volumeName string, info *VolumeInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get disk usage from df stats
	dfCmd := eos_cli.Wrap(rc, "ceph", "fs", "df", volumeName, "--format", "json")
	output, err := dfCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get disk usage: %w", err)
	}

	var dfStats struct {
		Stats struct {
			TotalBytes int64 `json:"total_bytes"`
			UsedBytes  int64 `json:"used_bytes"`
			AvailBytes int64 `json:"avail_bytes"`
		} `json:"stats"`
	}

	if err := json.Unmarshal(output, &dfStats); err == nil {
		info.Size = dfStats.Stats.TotalBytes
		info.UsedSize = dfStats.Stats.UsedBytes
		info.AvailableSize = dfStats.Stats.AvailBytes

		logger.Debug("Disk usage retrieved",
			zap.Int64("totalBytes", info.Size),
			zap.Int64("usedBytes", info.UsedSize),
			zap.Int64("availableBytes", info.AvailableSize))
	}

	return nil
}

func readMountPoints(rc *eos_io.RuntimeContext, volumeName string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Find all CephFS mounts
	findmntCmd := eos_cli.Wrap(rc, "findmnt", "-t", "ceph", "-n", "-o", "TARGET,SOURCE")
	output, err := findmntCmd.Output()
	if err != nil {
		return nil, err
	}

	mountPoints := []string{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			// Check if this mount is for our volume
			if strings.Contains(parts[1], volumeName) {
				mountPoints = append(mountPoints, parts[0])
			}
		}
	}

	logger.Debug("Found mount points",
		zap.String("volume", volumeName),
		zap.Int("count", len(mountPoints)))

	return mountPoints, nil
}

func getVolumePools(rc *eos_io.RuntimeContext, volumeName string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	pools := []string{}

	// Get volume details
	getCmd := eos_cli.Wrap(rc, "ceph", "fs", "get", volumeName, "--format", "json")
	output, err := getCmd.Output()
	if err != nil {
		return nil, err
	}

	var volumeInfo map[string]interface{}
	if err := json.Unmarshal(output, &volumeInfo); err != nil {
		return nil, err
	}

	// Extract data pools
	if dataPools, ok := volumeInfo["data_pools"].([]interface{}); ok {
		for _, pool := range dataPools {
			if poolName, ok := pool.(string); ok {
				pools = append(pools, poolName)
			}
		}
	}

	// Extract metadata pool
	if metadataPool, ok := volumeInfo["metadata_pool"].(string); ok {
		pools = append(pools, metadataPool)
	}

	logger.Debug("Retrieved volume pools",
		zap.String("volume", volumeName),
		zap.Strings("pools", pools))

	return pools, nil
}

func getPoolStats(rc *eos_io.RuntimeContext, poolName string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)

	stats := make(map[string]interface{})

	// Get pool statistics
	statsCmd := eos_cli.Wrap(rc, "ceph", "osd", "pool", "stats", poolName, "--format", "json")
	output, err := statsCmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse the output
	var poolStats []map[string]interface{}
	if err := json.Unmarshal(output, &poolStats); err != nil {
		return nil, err
	}

	if len(poolStats) > 0 {
		poolStat := poolStats[0]

		// Extract relevant statistics
		if clientIO, ok := poolStat["client_io_rate"].(map[string]interface{}); ok {
			stats["client_io_rate"] = clientIO
		}

		if recovery, ok := poolStat["recovery_rate"].(map[string]interface{}); ok {
			stats["recovery_rate"] = recovery
		}

		logger.Debug("Pool statistics retrieved",
			zap.String("pool", poolName),
			zap.Int("statCount", len(stats)))
	}

	return stats, nil
}
