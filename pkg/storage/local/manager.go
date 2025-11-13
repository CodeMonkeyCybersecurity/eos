package local

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LocalStorageManager manages local disk storage without LVM
type LocalStorageManager struct {
	logger    otelzap.LoggerWithCtx
	rc        *eos_io.RuntimeContext
	basePath  string
	mountOpts []string
}

// DiskInfo represents information about a disk
type DiskInfo struct {
	Device     string `json:"device"`
	Size       int64  `json:"size"`
	Used       int64  `json:"used"`
	Available  int64  `json:"available"`
	Filesystem string `json:"filesystem"`
	MountPoint string `json:"mount_point"`
	UUID       string `json:"uuid"`
}

// VolumeSpec defines volume creation parameters
type VolumeSpec struct {
	Name       string `json:"name"`
	Device     string `json:"device"`
	Size       string `json:"size"`
	Filesystem string `json:"filesystem"`
	MountPoint string `json:"mount_point"`
	Options    []string `json:"options"`
}

func NewLocalStorageManager(rc *eos_io.RuntimeContext) *LocalStorageManager {
	logger := otelzap.Ctx(rc.Ctx)
	return &LocalStorageManager{
		logger:    logger,
		rc:        rc,
		basePath:  "",
		mountOpts: []string{"defaults", "nofail"},
	}
}

// CreateVolume creates and formats a volume using modern Linux tools
func (lsm *LocalStorageManager) CreateVolume(ctx context.Context, spec *VolumeSpec) (*DiskInfo, error) {
	lsm.logger.Info("Creating volume",
		zap.String("name", spec.Name),
		zap.String("device", spec.Device),
		zap.String("filesystem", spec.Filesystem))

	// 1. Check if device exists and is not mounted
	if err := lsm.validateDevice(spec.Device); err != nil {
		return nil, fmt.Errorf("device validation failed: %w", err)
	}

	// 2. Create filesystem using modern tools
	if err := lsm.createFilesystem(ctx, spec.Device, spec.Filesystem); err != nil {
		return nil, fmt.Errorf("filesystem creation failed: %w", err)
	}

	// 3. Create mount point
	if err := os.MkdirAll(spec.MountPoint, shared.ServiceDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create mount point: %w", err)
	}

	// 4. Get UUID for persistent mounting
	uuid, err := lsm.getDeviceUUID(spec.Device)
	if err != nil {
		return nil, fmt.Errorf("failed to get device UUID: %w", err)
	}

	// 5. Update /etc/fstab
	if err := lsm.updateFstab(uuid, spec.MountPoint, spec.Filesystem, spec.Options); err != nil {
		return nil, fmt.Errorf("failed to update fstab: %w", err)
	}

	// 6. Mount the volume
	if err := lsm.mountVolume(spec.MountPoint); err != nil {
		return nil, fmt.Errorf("failed to mount volume: %w", err)
	}

	// 7. Get disk info
	diskInfo, err := lsm.getDiskInfo(spec.Device, spec.MountPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get disk info: %w", err)
	}

	lsm.logger.Info("Volume created successfully",
		zap.String("device", spec.Device),
		zap.String("mount_point", spec.MountPoint),
		zap.String("uuid", uuid))

	return diskInfo, nil
}

// validateDevice checks if device is valid and available
func (lsm *LocalStorageManager) validateDevice(device string) error {
	// Check if device exists
	if _, err := os.Stat(device); os.IsNotExist(err) {
		return fmt.Errorf("device %s does not exist", device)
	}

	// Check if device is already mounted
	cmd := exec.Command("findmnt", "-n", "-o", "TARGET", device)
	output, err := cmd.Output()
	if err == nil && len(strings.TrimSpace(string(output))) > 0 {
		return fmt.Errorf("device %s is already mounted at %s", device, strings.TrimSpace(string(output)))
	}

	return nil
}

// createFilesystem creates filesystem without LVM
func (lsm *LocalStorageManager) createFilesystem(ctx context.Context, device, fsType string) error {
	var cmd *exec.Cmd

	switch fsType {
	case "ext4":
		cmd = exec.CommandContext(ctx, "mkfs.ext4", "-F", device)
	case "xfs":
		cmd = exec.CommandContext(ctx, "mkfs.xfs", "-f", device)
	case "btrfs":
		cmd = exec.CommandContext(ctx, "mkfs.btrfs", "-f", device)
	default:
		return fmt.Errorf("unsupported filesystem type: %s", fsType)
	}

	lsm.logger.Info("Creating filesystem", 
		zap.String("device", device),
		zap.String("type", fsType))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkfs failed: %w, output: %s", err, string(output))
	}

	return nil
}

// getDeviceUUID gets the UUID of a device
func (lsm *LocalStorageManager) getDeviceUUID(device string) (string, error) {
	cmd := exec.Command("blkid", "-s", "UUID", "-o", "value", device)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get UUID: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// updateFstab adds entry to /etc/fstab
func (lsm *LocalStorageManager) updateFstab(uuid, mountPoint, fsType string, options []string) error {
	fstabEntry := fmt.Sprintf("UUID=%s %s %s %s 0 2\n", 
		uuid, mountPoint, fsType, strings.Join(append(lsm.mountOpts, options...), ","))

	// Check if entry already exists
	fstabContent, err := os.ReadFile("/etc/fstab")
	if err != nil {
		return fmt.Errorf("failed to read fstab: %w", err)
	}

	if strings.Contains(string(fstabContent), uuid) {
		lsm.logger.Info("Fstab entry already exists", zap.String("uuid", uuid))
		return nil
	}

	// Append to fstab
	f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open fstab: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(fstabEntry); err != nil {
		return fmt.Errorf("failed to write fstab entry: %w", err)
	}

	return nil
}

// mountVolume mounts the volume
func (lsm *LocalStorageManager) mountVolume(mountPoint string) error {
	cmd := exec.Command("mount", mountPoint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount failed: %w, output: %s", err, string(output))
	}

	return nil
}

// getDiskInfo retrieves disk information
func (lsm *LocalStorageManager) getDiskInfo(device, mountPoint string) (*DiskInfo, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &stat); err != nil {
		return nil, fmt.Errorf("failed to get filesystem stats: %w", err)
	}

	blockSize := int64(stat.Bsize)
	totalSize := int64(stat.Blocks) * blockSize
	availableSize := int64(stat.Bavail) * blockSize
	usedSize := totalSize - availableSize

	// Get filesystem type
	cmd := exec.Command("findmnt", "-n", "-o", "FSTYPE", mountPoint)
	output, err := cmd.Output()
	fsType := "unknown"
	if err == nil {
		fsType = strings.TrimSpace(string(output))
	}

	// Get UUID
	uuid, _ := lsm.getDeviceUUID(device)

	return &DiskInfo{
		Device:     device,
		Size:       totalSize,
		Used:       usedSize,
		Available:  availableSize,
		Filesystem: fsType,
		MountPoint: mountPoint,
		UUID:       uuid,
	}, nil
}

// ResizeVolume resizes a volume (ext4/xfs only)
func (lsm *LocalStorageManager) ResizeVolume(ctx context.Context, device string) error {
	// Get filesystem type
	cmd := exec.Command("findmnt", "-n", "-o", "FSTYPE", device)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to determine filesystem type: %w", err)
	}

	fsType := strings.TrimSpace(string(output))

	switch fsType {
	case "ext4":
		cmd = exec.CommandContext(ctx, "resize2fs", device)
	case "xfs":
		mountPoint, err := lsm.getMountPoint(device)
		if err != nil {
			return fmt.Errorf("failed to get mount point: %w", err)
		}
		cmd = exec.CommandContext(ctx, "xfs_growfs", mountPoint)
	default:
		return fmt.Errorf("resize not supported for filesystem type: %s", fsType)
	}

	lsm.logger.Info("Resizing volume", 
		zap.String("device", device),
		zap.String("filesystem", fsType))

	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("resize failed: %w, output: %s", err, string(output))
	}

	return nil
}

// getMountPoint gets the mount point for a device
func (lsm *LocalStorageManager) getMountPoint(device string) (string, error) {
	cmd := exec.Command("findmnt", "-n", "-o", "TARGET", device)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to find mount point: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// ListVolumes lists all managed volumes
func (lsm *LocalStorageManager) ListVolumes(ctx context.Context) ([]*DiskInfo, error) {
	cmd := exec.Command("findmnt", "-J", "-t", "ext4,xfs,btrfs")
	_, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	// Parse JSON output and convert to DiskInfo
	// This is a simplified version - you'd want proper JSON parsing
	var volumes []*DiskInfo

	// For now, return empty list - implement JSON parsing as needed
	return volumes, nil
}

// DeleteVolume unmounts and removes a volume
func (lsm *LocalStorageManager) DeleteVolume(ctx context.Context, mountPoint string) error {
	lsm.logger.Info("Deleting volume", zap.String("mount_point", mountPoint))

	// 1. Unmount
	cmd := exec.CommandContext(ctx, "umount", mountPoint)
	if output, err := cmd.CombinedOutput(); err != nil {
		lsm.logger.Warn("Unmount failed", zap.Error(err), zap.String("output", string(output)))
	}

	// 2. Remove from fstab
	if err := lsm.removeFromFstab(mountPoint); err != nil {
		lsm.logger.Warn("Failed to remove from fstab", zap.Error(err))
	}

	// 3. Remove mount point
	if err := os.Remove(mountPoint); err != nil {
		lsm.logger.Warn("Failed to remove mount point", zap.Error(err))
	}

	return nil
}

// removeFromFstab removes an entry from /etc/fstab
func (lsm *LocalStorageManager) removeFromFstab(mountPoint string) error {
	content, err := os.ReadFile("/etc/fstab")
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string

	for _, line := range lines {
		if !strings.Contains(line, mountPoint) {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile("/etc/fstab", []byte(strings.Join(newLines, "\n")), shared.ConfigFilePerm)
}
