// pkg/storage_monitor/saltstack_disk_manager.go

package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiskManager defines the interface for disk management operations
type DiskManager interface {
	// Disk usage monitoring and reporting
	GetDiskUsage(ctx context.Context, target, path string) (*DiskUsage, error)
	GetAllDiskUsage(ctx context.Context, target string) ([]DiskUsage, error)

	// Disk space management
	CleanupTempFiles(ctx context.Context, target string, options CleanupOptions) (*DiskCleanupResult, error)
	ExpandFilesystem(ctx context.Context, target, device string) error

	// Mount point operations
	GetMountPoints(ctx context.Context, target string) ([]MountInfo, error)
	MountDevice(ctx context.Context, target, device, mountPoint, fsType string, options []string) error
	UnmountDevice(ctx context.Context, target, mountPoint string, force bool) error

	// Disk health checks and SMART data
	GetSMARTData(ctx context.Context, target, device string) (*SMARTData, error)
	CheckDiskHealth(ctx context.Context, target string) ([]SMARTData, error)

	// Storage allocation and partitioning
	GetPartitions(ctx context.Context, target, device string) ([]PartitionInfo, error)
	CreatePartition(ctx context.Context, target, device string, partition PartitionSpec) error
	DeletePartition(ctx context.Context, target, device string, partNumber int) error
}

// CleanupOptions defines options for disk cleanup operations
type CleanupOptions struct {
	TempDirs      []string      `json:"temp_dirs"`
	LogDirs       []string      `json:"log_dirs"`
	MaxAge        time.Duration `json:"max_age"`
	MinFreeSpace  int64         `json:"min_free_space"`
	DryRun        bool          `json:"dry_run"`
	IncludeHidden bool          `json:"include_hidden"`
}

// PartitionSpec defines partition creation specifications
type PartitionSpec struct {
	Start      string   `json:"start"`
	End        string   `json:"end"`
	Type       string   `json:"type"`
	Filesystem string   `json:"filesystem,omitempty"`
	Label      string   `json:"label,omitempty"`
	Flags      []string `json:"flags,omitempty"`
}

// SaltStackDiskManager implements DiskManager using SaltStack API
type SaltStackDiskManager struct {
	client saltstack.ClientInterface
	logger otelzap.LoggerWithCtx
	rc     *eos_io.RuntimeContext
}

// NewSaltStackDiskManager creates a new SaltStack disk manager
func NewSaltStackDiskManager(client saltstack.ClientInterface, rc *eos_io.RuntimeContext) *SaltStackDiskManager {
	return &SaltStackDiskManager{
		client: client,
		logger: otelzap.Ctx(rc.Ctx),
		rc:     rc,
	}
}

// GetDiskUsage retrieves disk usage for a specific path using SaltStack
func (dm *SaltStackDiskManager) GetDiskUsage(ctx context.Context, target, path string) (*DiskUsage, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Getting disk usage via SaltStack",
		zap.String("target", target),
		zap.String("path", path))

	// Use Salt's disk.usage module
	cmd := fmt.Sprintf("disk.usage %s", path)
	result, err := dm.client.CmdRun(ctx, target, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get disk usage for %s: %w", path, err)
	}

	usage, err := dm.parseDiskUsage(result, path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse disk usage result: %w", err)
	}

	return usage, nil
}

// GetAllDiskUsage retrieves disk usage for all mounted filesystems
func (dm *SaltStackDiskManager) GetAllDiskUsage(ctx context.Context, target string) ([]DiskUsage, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Getting all disk usage via SaltStack", zap.String("target", target))

	// Get all mount points first
	mounts, err := dm.GetMountPoints(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("failed to get mount points: %w", err)
	}

	var allUsage []DiskUsage
	for _, mount := range mounts {
		usage, err := dm.GetDiskUsage(ctx, target, mount.MountPoint)
		if err != nil {
			logger.Warn("Failed to get usage for mount point",
				zap.String("mount_point", mount.MountPoint),
				zap.Error(err))
			continue
		}
		allUsage = append(allUsage, *usage)
	}

	return allUsage, nil
}

// CleanupTempFiles performs disk cleanup operations
func (dm *SaltStackDiskManager) CleanupTempFiles(ctx context.Context, target string, options CleanupOptions) (*DiskCleanupResult, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Starting disk cleanup via SaltStack",
		zap.String("target", target),
		zap.Bool("dry_run", options.DryRun))

	startTime := time.Now()
	result := &DiskCleanupResult{
		Timestamp: startTime,
	}

	// Create cleanup pillar data
	pillar := map[string]interface{}{
		"cleanup_options": options,
	}

	// Apply cleanup state
	stateName := "disk.cleanup"
	if options.DryRun {
		stateName = "disk.cleanup_dry_run"
	}

	err := dm.client.StateApply(ctx, target, stateName, pillar)
	if err != nil {
		return nil, fmt.Errorf("failed to apply cleanup state: %w", err)
	}

	// Get cleanup results
	resultCmd := "grains.get cleanup_result"
	resultData, err := dm.client.CmdRun(ctx, target, resultCmd)
	if err != nil {
		logger.Warn("Failed to get cleanup results", zap.Error(err))
		// Return partial result
		result.Duration = time.Since(startTime)
		return result, nil
	}

	if err := dm.parseCleanupResult(resultData, result); err != nil {
		logger.Warn("Failed to parse cleanup results", zap.Error(err))
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// ExpandFilesystem expands a filesystem to use available space
func (dm *SaltStackDiskManager) ExpandFilesystem(ctx context.Context, target, device string) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Expanding filesystem via SaltStack",
		zap.String("target", target),
		zap.String("device", device))

	pillar := map[string]interface{}{
		"device": device,
	}

	err := dm.client.StateApply(ctx, target, "disk.expand_filesystem", pillar)
	if err != nil {
		return fmt.Errorf("failed to expand filesystem on %s: %w", device, err)
	}

	return nil
}

// GetMountPoints retrieves all mount points
func (dm *SaltStackDiskManager) GetMountPoints(ctx context.Context, target string) ([]MountInfo, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Getting mount points via SaltStack", zap.String("target", target))

	result, err := dm.client.CmdRun(ctx, target, "mount.active")
	if err != nil {
		return nil, fmt.Errorf("failed to get mount points: %w", err)
	}

	mounts, err := dm.parseMountPoints(result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mount points: %w", err)
	}

	return mounts, nil
}

// MountDevice mounts a device to a mount point
func (dm *SaltStackDiskManager) MountDevice(ctx context.Context, target, device, mountPoint, fsType string, options []string) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Mounting device via SaltStack",
		zap.String("target", target),
		zap.String("device", device),
		zap.String("mount_point", mountPoint),
		zap.String("fs_type", fsType))

	pillar := map[string]interface{}{
		"device":      device,
		"mount_point": mountPoint,
		"fs_type":     fsType,
		"options":     options,
	}

	err := dm.client.StateApply(ctx, target, "disk.mount", pillar)
	if err != nil {
		return fmt.Errorf("failed to mount %s to %s: %w", device, mountPoint, err)
	}

	return nil
}

// UnmountDevice unmounts a device from a mount point
func (dm *SaltStackDiskManager) UnmountDevice(ctx context.Context, target, mountPoint string, force bool) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Unmounting device via SaltStack",
		zap.String("target", target),
		zap.String("mount_point", mountPoint),
		zap.Bool("force", force))

	pillar := map[string]interface{}{
		"mount_point": mountPoint,
		"force":       force,
	}

	err := dm.client.StateApply(ctx, target, "disk.unmount", pillar)
	if err != nil {
		return fmt.Errorf("failed to unmount %s: %w", mountPoint, err)
	}

	return nil
}

// GetSMARTData retrieves SMART data for a specific device
func (dm *SaltStackDiskManager) GetSMARTData(ctx context.Context, target, device string) (*SMARTData, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Getting SMART data via SaltStack",
		zap.String("target", target),
		zap.String("device", device))

	cmd := fmt.Sprintf("disk.smart_attributes %s", device)
	result, err := dm.client.CmdRun(ctx, target, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get SMART data for %s: %w", device, err)
	}

	smartData, err := dm.parseSMARTData(result, device)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SMART data: %w", err)
	}

	return smartData, nil
}

// CheckDiskHealth checks health of all disks
func (dm *SaltStackDiskManager) CheckDiskHealth(ctx context.Context, target string) ([]SMARTData, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Checking disk health via SaltStack", zap.String("target", target))

	// Get list of block devices
	result, err := dm.client.CmdRun(ctx, target, "disk.blkid")
	if err != nil {
		return nil, fmt.Errorf("failed to get block devices: %w", err)
	}

	devices, err := dm.parseBlockDevices(result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block devices: %w", err)
	}

	var healthData []SMARTData
	for _, device := range devices {
		smart, err := dm.GetSMARTData(ctx, target, device)
		if err != nil {
			logger.Warn("Failed to get SMART data for device",
				zap.String("device", device),
				zap.Error(err))
			continue
		}
		healthData = append(healthData, *smart)
	}

	return healthData, nil
}

// GetPartitions retrieves partition information for a device
func (dm *SaltStackDiskManager) GetPartitions(ctx context.Context, target, device string) ([]PartitionInfo, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Getting partitions via SaltStack",
		zap.String("target", target),
		zap.String("device", device))

	cmd := fmt.Sprintf("partition.list %s", device)
	result, err := dm.client.CmdRun(ctx, target, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get partitions for %s: %w", device, err)
	}

	partitions, err := dm.parsePartitions(result, device)
	if err != nil {
		return nil, fmt.Errorf("failed to parse partitions: %w", err)
	}

	return partitions, nil
}

// CreatePartition creates a new partition on a device
func (dm *SaltStackDiskManager) CreatePartition(ctx context.Context, target, device string, partition PartitionSpec) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Creating partition via SaltStack",
		zap.String("target", target),
		zap.String("device", device),
		zap.String("type", partition.Type))

	pillar := map[string]interface{}{
		"device":    device,
		"partition": partition,
	}

	err := dm.client.StateApply(ctx, target, "disk.create_partition", pillar)
	if err != nil {
		return fmt.Errorf("failed to create partition on %s: %w", device, err)
	}

	return nil
}

// DeletePartition deletes a partition from a device
func (dm *SaltStackDiskManager) DeletePartition(ctx context.Context, target, device string, partNumber int) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Deleting partition via SaltStack",
		zap.String("target", target),
		zap.String("device", device),
		zap.Int("partition", partNumber))

	pillar := map[string]interface{}{
		"device":           device,
		"partition_number": partNumber,
	}

	err := dm.client.StateApply(ctx, target, "disk.delete_partition", pillar)
	if err != nil {
		return fmt.Errorf("failed to delete partition %d on %s: %w", partNumber, device, err)
	}

	return nil
}

// Helper methods for parsing SaltStack responses

func (dm *SaltStackDiskManager) parseDiskUsage(result, path string) (*DiskUsage, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal disk usage data: %w", err)
	}

	usage := &DiskUsage{
		Path:      path,
		Timestamp: time.Now(),
	}

	if total, ok := data["total"].(float64); ok {
		usage.TotalSize = int64(total)
	}
	if used, ok := data["used"].(float64); ok {
		usage.UsedSize = int64(used)
	}
	if available, ok := data["available"].(float64); ok {
		usage.AvailableSize = int64(available)
	}
	if percent, ok := data["percent"].(float64); ok {
		usage.UsedPercent = percent
	}

	return usage, nil
}

func (dm *SaltStackDiskManager) parseCleanupResult(result string, cleanup *DiskCleanupResult) error {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		return fmt.Errorf("failed to unmarshal cleanup result: %w", err)
	}

	if freed, ok := data["freed_bytes"].(float64); ok {
		cleanup.FreedBytes = int64(freed)
	}
	if files, ok := data["files_removed"].(float64); ok {
		cleanup.FilesRemoved = int(files)
	}
	if dirs, ok := data["dirs_removed"].(float64); ok {
		cleanup.DirsRemoved = int(dirs)
	}

	return nil
}

func (dm *SaltStackDiskManager) parseMountPoints(result string) ([]MountInfo, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mount data: %w", err)
	}

	var mounts []MountInfo
	timestamp := time.Now()

	for mountPoint, info := range data {
		if mountInfo, ok := info.(map[string]interface{}); ok {
			mount := MountInfo{
				MountPoint: mountPoint,
				Timestamp:  timestamp,
			}

			if device, ok := mountInfo["device"].(string); ok {
				mount.Device = device
			}
			if fstype, ok := mountInfo["fstype"].(string); ok {
				mount.Filesystem = fstype
			}
			if opts, ok := mountInfo["opts"].([]interface{}); ok {
				for _, opt := range opts {
					if optStr, ok := opt.(string); ok {
						mount.Options = append(mount.Options, optStr)
					}
				}
			}

			mounts = append(mounts, mount)
		}
	}

	return mounts, nil
}

func (dm *SaltStackDiskManager) parseSMARTData(result, device string) (*SMARTData, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SMART data: %w", err)
	}

	smart := &SMARTData{
		Device:    device,
		Timestamp: time.Now(),
	}

	if model, ok := data["model"].(string); ok {
		smart.Model = model
	}
	if serial, ok := data["serial"].(string); ok {
		smart.SerialNumber = serial
	}
	if health, ok := data["health"].(string); ok {
		smart.OverallHealth = health
	}

	return smart, nil
}

func (dm *SaltStackDiskManager) parseBlockDevices(result string) ([]string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block device data: %w", err)
	}

	var devices []string
	for device := range data {
		// Filter out partitions, keep only main devices
		if !strings.Contains(device, "p") && !strings.ContainsAny(device, "0123456789") {
			devices = append(devices, device)
		}
	}

	return devices, nil
}

func (dm *SaltStackDiskManager) parsePartitions(result, device string) ([]PartitionInfo, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal partition data: %w", err)
	}

	var partitions []PartitionInfo
	timestamp := time.Now()

	for partName, info := range data {
		if partInfo, ok := info.(map[string]interface{}); ok {
			partition := PartitionInfo{
				Device:    partName,
				Timestamp: timestamp,
			}

			if size, ok := partInfo["size"].(string); ok {
				if sizeInt, err := strconv.ParseUint(size, 10, 64); err == nil {
					partition.Size = sizeInt
				}
			}
			if fstype, ok := partInfo["fstype"].(string); ok {
				partition.Filesystem = fstype
			}
			if uuid, ok := partInfo["uuid"].(string); ok {
				partition.UUID = uuid
			}

			partitions = append(partitions, partition)
		}
	}

	return partitions, nil
}
