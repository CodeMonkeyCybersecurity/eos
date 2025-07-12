package storage

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VolumeGroup represents an LVM volume group
type VolumeGroup struct {
	Name      string
	Size      string
	Free      string
	PVCount   string
	LVCount   string
	SnapCount string
}

// LogicalVolume represents an LVM logical volume
type LogicalVolume struct {
	Name string
	VG   string
	Size string
	Path string
}

// DisplayVolumeGroups shows volume group information
func DisplayVolumeGroups(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.DisplayVolumeGroups")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Displaying volume groups")

	cmd := exec.CommandContext(ctx, "vgdisplay")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to run vgdisplay", zap.Error(err))
		return fmt.Errorf("failed to run vgdisplay: %w", err)
	}

	logger.Info("Volume group information:")
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		logger.Info(scanner.Text())
	}

	return nil
}

// DisplayLogicalVolumes shows logical volume information
func DisplayLogicalVolumes(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.DisplayLogicalVolumes")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Displaying logical volumes")

	cmd := exec.CommandContext(ctx, "lvdisplay")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to run lvdisplay", zap.Error(err))
		return fmt.Errorf("failed to run lvdisplay: %w", err)
	}

	logger.Info("Logical volume information:")
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		logger.Info(scanner.Text())
	}

	return nil
}

// ExtendLogicalVolume extends a logical volume to use all available space in the volume group
func ExtendLogicalVolume(rc *eos_io.RuntimeContext, lvPath string) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.ExtendLogicalVolume")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Extending logical volume", zap.String("lv_path", lvPath))

	// Extend the logical volume to use all free space
	cmd := exec.CommandContext(ctx, "lvextend", "-l", "+100%FREE", lvPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to extend logical volume",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("failed to extend logical volume %s: %w", lvPath, err)
	}

	logger.Info("Logical volume extended successfully",
		zap.String("lv_path", lvPath),
		zap.String("output", string(output)))
	return nil
}

// ResizeExt4Filesystem resizes an ext4 filesystem to use all available space
func ResizeExt4Filesystem(rc *eos_io.RuntimeContext, devicePath string) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.ResizeExt4Filesystem")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Resizing ext4 filesystem", zap.String("device_path", devicePath))

	// Resize the ext4 filesystem
	cmd := exec.CommandContext(ctx, "resize2fs", devicePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to resize filesystem",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("failed to resize filesystem %s: %w", devicePath, err)
	}

	logger.Info("Filesystem resized successfully",
		zap.String("device_path", devicePath),
		zap.String("output", string(output)))
	return nil
}

// ResizeXfsFilesystem resizes an XFS filesystem to use all available space
func ResizeXfsFilesystem(rc *eos_io.RuntimeContext, mountpoint string) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.ResizeXfsFilesystem")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Resizing XFS filesystem", zap.String("mountpoint", mountpoint))

	// Resize the XFS filesystem
	cmd := exec.CommandContext(ctx, "xfs_growfs", mountpoint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to resize XFS filesystem",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("failed to resize XFS filesystem %s: %w", mountpoint, err)
	}

	logger.Info("XFS filesystem resized successfully",
		zap.String("mountpoint", mountpoint),
		zap.String("output", string(output)))
	return nil
}

// AutoResizeUbuntuLVM automatically resizes the standard Ubuntu LVM setup
func AutoResizeUbuntuLVM(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "storage.AutoResizeUbuntuLVM")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting automatic Ubuntu LVM resize")

	// Display current volume group status
	if err := DisplayVolumeGroups(rc); err != nil {
		logger.Warn("Failed to display volume groups", zap.Error(err))
	}

	// Standard Ubuntu LVM paths
	lvPath := "/dev/ubuntu-vg/ubuntu-lv"
	mapperPath := "/dev/mapper/ubuntu--vg-ubuntu--lv"

	// Extend the logical volume
	logger.Info("Step 1: Extending logical volume")
	if err := ExtendLogicalVolume(rc, lvPath); err != nil {
		return err
	}

	// Resize the filesystem
	logger.Info("Step 2: Resizing filesystem")
	if err := ResizeExt4Filesystem(rc, mapperPath); err != nil {
		return err
	}

	// Display updated information
	logger.Info("Step 3: Displaying updated information")

	// Show disk usage
	usage, err := GetDiskUsage(rc)
	if err != nil {
		logger.Warn("Failed to get disk usage", zap.Error(err))
	} else {
		logger.Info("Updated disk usage:")
		scanner := bufio.NewScanner(strings.NewReader(usage))
		for scanner.Scan() {
			logger.Info(scanner.Text())
		}
	}

	// Show block devices
	cmd := exec.CommandContext(ctx, "lsblk")
	output, err := cmd.Output()
	if err != nil {
		logger.Warn("Failed to run lsblk", zap.Error(err))
	} else {
		logger.Info("Updated block device information:")
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			logger.Info(scanner.Text())
		}
	}

	// Display logical volumes
	if err := DisplayLogicalVolumes(rc); err != nil {
		logger.Warn("Failed to display logical volumes", zap.Error(err))
	}

	logger.Info("Ubuntu LVM resize completed successfully")
	return nil
}

// GetVolumeGroups parses vgdisplay output and returns structured data
func GetVolumeGroups(rc *eos_io.RuntimeContext) ([]VolumeGroup, error) {
	ctx, span := telemetry.Start(rc.Ctx, "storage.GetVolumeGroups")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting volume groups information")

	cmd := exec.CommandContext(ctx, "vgs", "--noheadings", "--separator", ",")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to run vgs", zap.Error(err))
		return nil, fmt.Errorf("failed to run vgs: %w", err)
	}

	var vgs []VolumeGroup
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 6 {
			vg := VolumeGroup{
				Name:      strings.TrimSpace(fields[0]),
				PVCount:   strings.TrimSpace(fields[1]),
				LVCount:   strings.TrimSpace(fields[2]),
				SnapCount: strings.TrimSpace(fields[3]),
				Size:      strings.TrimSpace(fields[5]),
				Free:      strings.TrimSpace(fields[6]),
			}
			vgs = append(vgs, vg)
		}
	}

	logger.Info("Found volume groups", zap.Int("count", len(vgs)))
	return vgs, nil
}

// GetLogicalVolumes parses lvdisplay output and returns structured data
func GetLogicalVolumes(rc *eos_io.RuntimeContext) ([]LogicalVolume, error) {
	ctx, span := telemetry.Start(rc.Ctx, "storage.GetLogicalVolumes")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting logical volumes information")

	cmd := exec.CommandContext(ctx, "lvs", "--noheadings", "--separator", ",")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to run lvs", zap.Error(err))
		return nil, fmt.Errorf("failed to run lvs: %w", err)
	}

	var lvs []LogicalVolume
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 3 {
			lv := LogicalVolume{
				Name: strings.TrimSpace(fields[0]),
				VG:   strings.TrimSpace(fields[1]),
				Size: strings.TrimSpace(fields[4]),
				Path: fmt.Sprintf("/dev/%s/%s", strings.TrimSpace(fields[1]), strings.TrimSpace(fields[0])),
			}
			lvs = append(lvs, lv)
		}
	}

	logger.Info("Found logical volumes", zap.Int("count", len(lvs)))
	return lvs, nil
}
