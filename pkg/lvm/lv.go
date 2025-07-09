package lvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateLogicalVolume creates a new logical volume
func CreateLogicalVolume(rc *eos_io.RuntimeContext, config *LogicalVolumeConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing logical volume creation requirements",
		zap.String("name", config.Name),
		zap.String("vg", config.VolumeGroup),
		zap.String("size", config.Size))

	// Validate inputs
	if config.Name == "" || config.VolumeGroup == "" {
		return eos_err.NewUserError("logical volume name and volume group are required")
	}

	if config.Size == "" {
		return eos_err.NewUserError("logical volume size is required")
	}

	// Check if VG exists
	vg, err := GetVolumeGroup(rc, config.VolumeGroup)
	if err != nil {
		return eos_err.NewUserError("volume group not found: %s", config.VolumeGroup)
	}

	// Check if LV already exists
	lvPath := fmt.Sprintf("/dev/%s/%s", config.VolumeGroup, config.Name)
	checkCmd := exec.CommandContext(rc.Ctx, "lvdisplay", lvPath)
	if err := checkCmd.Run(); err == nil {
		return eos_err.NewUserError("logical volume %s already exists in volume group %s",
			config.Name, config.VolumeGroup)
	}

	// Check available space
	sizeBytes, err := parseSize(config.Size)
	if err != nil {
		return eos_err.NewUserError("invalid size format: %s", config.Size)
	}

	if sizeBytes > vg.Free {
		return eos_err.NewUserError("insufficient free space in volume group. Requested: %s, Available: %d bytes",
			config.Size, vg.Free)
	}

	// INTERVENE
	logger.Info("Creating logical volume",
		zap.String("name", config.Name),
		zap.String("vg", config.VolumeGroup),
		zap.String("type", config.Type))

	// Build lvcreate command
	args := []string{"lvcreate", "-y", "-n", config.Name, "-L", config.Size}

	// Add type-specific options
	switch config.Type {
	case "striped":
		if config.Stripes > 0 {
			args = append(args, "-i", fmt.Sprintf("%d", config.Stripes))
		}
		if config.StripeSize != "" {
			args = append(args, "-I", config.StripeSize)
		}
	case "mirror":
		if config.MirrorCount > 0 {
			args = append(args, "-m", fmt.Sprintf("%d", config.MirrorCount))
		}
	case "thin":
		if config.ThinPool != "" {
			args = append(args, "--thinpool", config.ThinPool)
		}
	case "raid":
		args = append(args, "--type", "raid1")
	}

	args = append(args, config.VolumeGroup)

	createCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	output, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create logical volume: %w, output: %s", err, string(output))
	}

	logger.Debug("Logical volume created",
		zap.String("output", string(output)))

	// Create filesystem if specified
	if config.FileSystem != "" {
		if err := createFilesystem(rc, lvPath, config); err != nil {
			// Rollback LV creation
			logger.Warn("Failed to create filesystem, rolling back LV creation",
				zap.Error(err))
			removeCmd := exec.CommandContext(rc.Ctx, "lvremove", "-y", "-f", lvPath)
			removeCmd.Run()
			return fmt.Errorf("failed to create filesystem: %w", err)
		}
	}

	// Mount if mount point specified
	if config.MountPoint != "" {
		if err := mountLogicalVolume(rc, lvPath, config); err != nil {
			logger.Warn("Failed to mount logical volume",
				zap.Error(err))
		}
	}

	// EVALUATE
	logger.Info("Verifying logical volume creation")

	// Verify LV was created
	lvInfo, err := GetLogicalVolume(rc, config.VolumeGroup, config.Name)
	if err != nil {
		return fmt.Errorf("logical volume verification failed: %w", err)
	}

	if lvInfo.Name != config.Name {
		return fmt.Errorf("logical volume verification failed: name mismatch")
	}

	logger.Info("Logical volume created successfully",
		zap.String("path", lvInfo.Path),
		zap.Int64("size", lvInfo.Size),
		zap.String("filesystem", config.FileSystem))

	return nil
}

// GetLogicalVolume retrieves information about a logical volume
func GetLogicalVolume(rc *eos_io.RuntimeContext, vgName, lvName string) (*LogicalVolume, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing logical volume",
		zap.String("vg", vgName),
		zap.String("lv", lvName))

	// INTERVENE
	logger.Info("Reading logical volume information")

	lvPath := fmt.Sprintf("%s/%s", vgName, lvName)

	// Get detailed information using lvs
	lvsCmd := exec.CommandContext(rc.Ctx, "lvs", "--units", "b", "--noheadings", "-o",
		"lv_name,lv_path,vg_name,lv_uuid,lv_size,origin,lv_attr,lv_kernel_major,lv_kernel_minor,seg_count",
		"--separator", "|", lvPath)

	output, err := lvsCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("logical volume not found: %w", err)
	}

	fields := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(fields) < 10 {
		return nil, fmt.Errorf("unexpected lvs output format")
	}

	lv := &LogicalVolume{
		Name:        strings.TrimSpace(fields[0]),
		Path:        strings.TrimSpace(fields[1]),
		VolumeGroup: strings.TrimSpace(fields[2]),
		UUID:        strings.TrimSpace(fields[3]),
		Origin:      strings.TrimSpace(fields[5]),
		Attributes:  strings.TrimSpace(fields[6]),
	}

	// Parse size
	if size, err := parseSizeBytes(fields[4]); err == nil {
		lv.Size = size
	}

	// Parse segments
	if segments, err := parseIntValue(fields[9]); err == nil {
		lv.Segments = int(segments)
	}

	// Determine type from attributes
	attrs := lv.Attributes
	if len(attrs) > 0 {
		switch attrs[0] {
		case 'm':
			lv.Type = "mirror"
		case 'M':
			lv.Type = "mirror-no-log"
		case 'o':
			lv.Type = "origin"
		case 'O':
			lv.Type = "origin-merging"
		case 'r':
			lv.Type = "raid"
		case 'R':
			lv.Type = "raid-no-sync"
		case 's':
			lv.Type = "snapshot"
		case 'S':
			lv.Type = "snapshot-invalid"
		case 'p':
			lv.Type = "pvmove"
		case 'v':
			lv.Type = "virtual"
		case 'i':
			lv.Type = "mirror-image"
		case 'I':
			lv.Type = "raid-image"
		case 't':
			lv.Type = "thin"
		case 'T':
			lv.Type = "thin-pool"
		case 'e':
			lv.Type = "metadata"
		default:
			lv.Type = "linear"
		}
	}

	// Check mount status
	if mountPoint, err := getMountPoint(rc, lv.Path); err == nil && mountPoint != "" {
		lv.MountPoint = mountPoint
	}

	// Get filesystem type
	if fsType, err := getFilesystemType(rc, lv.Path); err == nil {
		lv.FileSystem = fsType
	}

	// EVALUATE
	logger.Info("Logical volume information retrieved",
		zap.String("name", lv.Name),
		zap.String("path", lv.Path),
		zap.String("type", lv.Type),
		zap.Int64("size", lv.Size))

	return lv, nil
}

// ResizeLogicalVolume resizes a logical volume
func ResizeLogicalVolume(rc *eos_io.RuntimeContext, vgName, lvName, newSize string, resizeFS bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing logical volume for resize",
		zap.String("vg", vgName),
		zap.String("lv", lvName),
		zap.String("newSize", newSize))

	// Get current LV info
	lv, err := GetLogicalVolume(rc, vgName, lvName)
	if err != nil {
		return eos_err.NewUserError("logical volume not found: %s/%s", vgName, lvName)
	}

	oldSize := lv.Size

	// Parse new size
	var sizeChange string
	if strings.HasPrefix(newSize, "+") || strings.HasPrefix(newSize, "-") {
		// Relative size change
		sizeChange = newSize
	} else {
		// Absolute size
		sizeChange = newSize

		// Validate new size
		newSizeBytes, err := parseSize(newSize)
		if err != nil {
			return eos_err.NewUserError("invalid size format: %s", newSize)
		}

		if newSizeBytes < oldSize {
			// Shrinking - need to check filesystem first
			if lv.FileSystem != "" && resizeFS {
				logger.Info("Shrinking filesystem before reducing LV")
				if err := shrinkFilesystem(rc, lv.Path, lv.FileSystem, newSizeBytes); err != nil {
					return fmt.Errorf("failed to shrink filesystem: %w", err)
				}
			}
		}
	}

	// INTERVENE
	logger.Info("Resizing logical volume",
		zap.String("path", lv.Path),
		zap.String("sizeChange", sizeChange))

	// Build resize command
	args := []string{"lvresize", "-y"}

	if resizeFS && lv.FileSystem != "" {
		// Use -r flag to resize filesystem automatically
		args = append(args, "-r")
	}

	args = append(args, "-L", sizeChange, lv.Path)

	resizeCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	output, err := resizeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to resize logical volume: %w, output: %s", err, string(output))
	}

	logger.Debug("Resize output",
		zap.String("output", string(output)))

	// EVALUATE
	logger.Info("Verifying logical volume resize")

	// Get new LV info
	newLV, err := GetLogicalVolume(rc, vgName, lvName)
	if err != nil {
		return fmt.Errorf("failed to verify resize: %w", err)
	}

	logger.Info("Logical volume resized successfully",
		zap.String("path", lv.Path),
		zap.Int64("oldSize", oldSize),
		zap.Int64("newSize", newLV.Size),
		zap.Int64("sizeDiff", newLV.Size-oldSize))

	return nil
}

// RemoveLogicalVolume removes a logical volume
func RemoveLogicalVolume(rc *eos_io.RuntimeContext, vgName, lvName string, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing logical volume for removal",
		zap.String("vg", vgName),
		zap.String("lv", lvName))

	// Get LV info
	lv, err := GetLogicalVolume(rc, vgName, lvName)
	if err != nil {
		return eos_err.NewUserError("logical volume not found: %s/%s", vgName, lvName)
	}

	// Check if mounted
	if lv.MountPoint != "" && !force {
		return eos_err.NewUserError("logical volume is mounted at %s. Unmount first or use --force", lv.MountPoint)
	}

	// Check if it's an origin for snapshots
	if hasSnapshots(rc, lv.Path) && !force {
		return eos_err.NewUserError("logical volume has snapshots. Remove them first or use --force")
	}

	// INTERVENE
	logger.Info("Removing logical volume",
		zap.String("path", lv.Path),
		zap.Bool("force", force))

	// Unmount if needed
	if lv.MountPoint != "" && force {
		logger.Debug("Force unmounting volume")
		umountCmd := exec.CommandContext(rc.Ctx, "umount", lv.MountPoint)
		if err := umountCmd.Run(); err != nil {
			logger.Warn("Failed to unmount volume",
				zap.String("mountPoint", lv.MountPoint),
				zap.Error(err))
		}
	}

	// Remove the LV
	args := []string{"lvremove", "-y"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, lv.Path)

	removeCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	output, err := removeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove logical volume: %w, output: %s", err, string(output))
	}

	// EVALUATE
	logger.Info("Verifying logical volume removal")

	// Verify LV was removed
	checkCmd := exec.CommandContext(rc.Ctx, "lvdisplay", lv.Path)
	if err := checkCmd.Run(); err == nil {
		return fmt.Errorf("logical volume removal verification failed: LV still exists")
	}

	logger.Info("Logical volume removed successfully",
		zap.String("path", lv.Path))

	return nil
}

// Helper functions

func createFilesystem(rc *eos_io.RuntimeContext, device string, config *LogicalVolumeConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating filesystem",
		zap.String("device", device),
		zap.String("type", config.FileSystem))

	var mkfsCmd *exec.Cmd

	switch config.FileSystem {
	case "xfs":
		args := []string{"mkfs.xfs", "-f"}

		// Add XFS-specific options for database optimization
		fsConfig := &FileSystemConfig{
			Type: "xfs",
			DatabaseOptimized: strings.Contains(config.Name, "postgres") ||
				strings.Contains(config.Name, "database") ||
				strings.Contains(config.Name, "db"),
		}

		if fsConfig.DatabaseOptimized {
			// Optimal settings for databases
			args = append(args, "-l", "size=256m", "-d", "su=64k,sw=1")
			logger.Debug("Using database-optimized XFS settings")
		}

		args = append(args, device)
		mkfsCmd = exec.CommandContext(rc.Ctx, args[0], args[1:]...)

	case "ext4":
		args := []string{"mkfs.ext4", "-F"}

		// Add ext4-specific options
		if strings.Contains(config.Name, "postgres") || strings.Contains(config.Name, "db") {
			// Optimize for databases
			args = append(args, "-O", "^has_journal", "-E", "stride=16,stripe_width=16")
			logger.Debug("Using database-optimized ext4 settings")
		}

		args = append(args, device)
		mkfsCmd = exec.CommandContext(rc.Ctx, args[0], args[1:]...)

	case "btrfs":
		mkfsCmd = exec.CommandContext(rc.Ctx, "mkfs.btrfs", "-f", device)

	default:
		return eos_err.NewUserError("unsupported filesystem type: %s", config.FileSystem)
	}

	output, err := mkfsCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create filesystem: %w, output: %s", err, string(output))
	}

	logger.Debug("Filesystem created",
		zap.String("output", string(output)))

	return nil
}

func mountLogicalVolume(rc *eos_io.RuntimeContext, device string, config *LogicalVolumeConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create mount point
	if err := os.MkdirAll(config.MountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}

	// Build mount options
	options := config.MountOptions
	if len(options) == 0 {
		// Use default options based on filesystem
		switch config.FileSystem {
		case "xfs":
			if strings.Contains(config.Name, "postgres") || strings.Contains(config.Name, "db") {
				options = XFSMountOptions["database"]
			} else {
				options = XFSMountOptions["general"]
			}
		case "ext4":
			if strings.Contains(config.Name, "postgres") || strings.Contains(config.Name, "db") {
				options = EXT4MountOptions["database"]
			} else {
				options = EXT4MountOptions["general"]
			}
		}
	}

	// Mount the filesystem
	args := []string{"mount"}
	if len(options) > 0 {
		args = append(args, "-o", strings.Join(options, ","))
	}
	args = append(args, device, config.MountPoint)

	mountCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to mount filesystem: %w, output: %s", err, string(output))
	}

	logger.Info("Filesystem mounted",
		zap.String("device", device),
		zap.String("mountPoint", config.MountPoint),
		zap.Strings("options", options))

	// Add to fstab for persistence
	if err := addToFstab(rc, device, config.MountPoint, config.FileSystem, options); err != nil {
		logger.Warn("Failed to add mount to fstab",
			zap.Error(err))
	}

	return nil
}

func parseSize(sizeStr string) (int64, error) {
	// Handle size formats like 10G, 100M, etc.
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	var multiplier int64 = 1
	var numStr string

	if strings.HasSuffix(sizeStr, "T") {
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "T")
	} else if strings.HasSuffix(sizeStr, "G") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "G")
	} else if strings.HasSuffix(sizeStr, "M") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(sizeStr, "M")
	} else if strings.HasSuffix(sizeStr, "K") {
		multiplier = 1024
		numStr = strings.TrimSuffix(sizeStr, "K")
	} else {
		numStr = sizeStr
	}

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, err
	}

	return int64(num * float64(multiplier)), nil
}

func getMountPoint(rc *eos_io.RuntimeContext, device string) (string, error) {
	findmntCmd := exec.CommandContext(rc.Ctx, "findmnt", "-n", "-o", "TARGET", device)
	output, err := findmntCmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

func getFilesystemType(rc *eos_io.RuntimeContext, device string) (string, error) {
	blkidCmd := exec.CommandContext(rc.Ctx, "blkid", "-o", "value", "-s", "TYPE", device)
	output, err := blkidCmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

func hasSnapshots(rc *eos_io.RuntimeContext, lvPath string) bool {
	// Check if LV has snapshots
	lvsCmd := exec.CommandContext(rc.Ctx, "lvs", "--noheadings", "-o", "lv_name", "-S",
		fmt.Sprintf("origin=%s", filepath.Base(lvPath)))

	if output, err := lvsCmd.Output(); err == nil {
		return strings.TrimSpace(string(output)) != ""
	}

	return false
}

func shrinkFilesystem(rc *eos_io.RuntimeContext, device, fsType string, newSize int64) error {
	logger := otelzap.Ctx(rc.Ctx)

	switch fsType {
	case "ext4", "ext3", "ext2":
		// Need to unmount first
		if mp, _ := getMountPoint(rc, device); mp != "" {
			umountCmd := exec.CommandContext(rc.Ctx, "umount", device)
			if err := umountCmd.Run(); err != nil {
				return fmt.Errorf("failed to unmount for resize: %w", err)
			}
			defer func() {
				// Remount after resize
				mountCmd := exec.CommandContext(rc.Ctx, "mount", device, mp)
				if err := mountCmd.Run(); err != nil {
					logger.Warn("Failed to remount after resize",
						zap.String("device", device),
						zap.Error(err))
				}
			}()
		}

		// Check filesystem
		e2fsckCmd := exec.CommandContext(rc.Ctx, "e2fsck", "-f", "-y", device)
		if err := e2fsckCmd.Run(); err != nil {
			logger.Warn("Filesystem check reported issues",
				zap.Error(err))
		}

		// Resize filesystem
		resize2fsCmd := exec.CommandContext(rc.Ctx, "resize2fs", device, fmt.Sprintf("%dK", newSize/1024))
		if output, err := resize2fsCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to resize ext filesystem: %w, output: %s", err, string(output))
		}

	case "xfs":
		return eos_err.NewUserError("XFS filesystems cannot be shrunk, only grown")

	case "btrfs":
		// BTRFS can be resized while mounted
		if mp, _ := getMountPoint(rc, device); mp != "" {
			btrfsCmd := exec.CommandContext(rc.Ctx, "btrfs", "filesystem", "resize",
				fmt.Sprintf("%d", newSize), mp)
			if output, err := btrfsCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to resize btrfs: %w, output: %s", err, string(output))
			}
		} else {
			return eos_err.NewUserError("BTRFS filesystem must be mounted to resize")
		}

	default:
		return eos_err.NewUserError("filesystem type %s does not support shrinking", fsType)
	}

	return nil
}

func addToFstab(rc *eos_io.RuntimeContext, device, mountPoint, fsType string, options []string) error {
	// Implementation would add the mount to /etc/fstab
	// Similar to the CephFS implementation
	return nil
}
